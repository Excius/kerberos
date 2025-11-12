import { useState, useEffect, useCallback } from "react";
import { useAuth } from "./useAuth";
import { toast } from "react-toastify";

const KDC_URL = "ws://localhost:8888"; // WebSocket URL for KDC
const TICKET_CACHE_KEY = "kerberos_tgt_cache";

async function sign_data(privateKey: CryptoKey, data: BufferSource) {
  return await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    data
  );
}

async function decrypt_with_private_key(
  privateKey: CryptoKey,
  encryptedB64: string
) {
  const encrypted = Uint8Array.from(atob(encryptedB64), (c) => c.charCodeAt(0));
  return await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encrypted
  );
}

export function useService() {
  const { user, keyPair } = useAuth();
  const [tgtObtained, setTgtObtained] = useState(false);
  const [services, setServices] = useState<
    { name: string; url: string; description: string; principal_name: string }[]
  >([]);
  const [serviceKeys, setServiceKeys] = useState<Record<string, string>>({});

  const listServices = useCallback(() => {
    const ws = new WebSocket(KDC_URL);
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "LIST_SERVICES" }));
    };
    ws.onmessage = (event) => {
      try {
        const response = JSON.parse(event.data);
        if (
          response.services &&
          Array.isArray(response.services) &&
          tgtObtained
        ) {
          setServices(response.services);
        }
      } catch {
        // ignore
      }
      ws.close();
    };
    ws.onerror = () => {};
    setTimeout(() => ws.close(), 5000);
  }, [tgtObtained]);

  const getTGT = async () => {
    const USER_PRINCIPAL = `${user!.username}@MYKERBEROSPROJECT`;
    const timestamp_str = new Date()
      .toISOString()
      .replace("Z", "+00:00")
      .replace(/\.\d{3}/, (match) => match + "000");
    const data_to_sign = {
      principal: USER_PRINCIPAL,
      timestamp: timestamp_str,
    };
    const canonical_json = JSON.stringify(
      data_to_sign,
      Object.keys(data_to_sign).sort()
    );
    const canonical_bytes = new TextEncoder().encode(canonical_json);

    const signature = await sign_data(keyPair!.privateKey, canonical_bytes);
    const signatureB64 = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    );

    const request_data = {
      type: "AS_REQ",
      cert_pem: user!.certificate,
      principal: USER_PRINCIPAL,
      timestamp: timestamp_str,
      signed_data: signatureB64,
    };

    // Use WebSocket for AS_REQ and LIST_SERVICES
    const ws = new WebSocket(KDC_URL);
    let asResponse: Record<string, unknown> | null = null;

    ws.onopen = () => {
      ws.send(JSON.stringify(request_data));
    };

    ws.onmessage = async (event) => {
      try {
        const response = JSON.parse(event.data);
        asResponse = response;
        ws.close(); // Close after receiving AS response
      } catch {
        ws.close();
      }
    };

    ws.onclose = async () => {
      if (asResponse) {
        // Process AS response
        if (asResponse.status === "OK") {
          const encrypted_key_b64 = asResponse.encrypted_session_key;
          if (typeof encrypted_key_b64 !== "string") {
            toast.error("Invalid response format");
            return;
          }
          try {
            // Export and re-import private key for decryption
            const privateKeyBuffer = await crypto.subtle.exportKey(
              "pkcs8",
              keyPair!.privateKey
            );
            const privateKeyForDecrypt = await crypto.subtle.importKey(
              "pkcs8",
              privateKeyBuffer,
              {
                name: "RSA-OAEP",
                hash: "SHA-256",
              },
              false,
              ["decrypt"]
            );

            const session_key = await decrypt_with_private_key(
              privateKeyForDecrypt,
              encrypted_key_b64
            );

            const cache_data = {
              principal: asResponse.principal,
              as_session_key: btoa(
                String.fromCharCode(...new Uint8Array(session_key))
              ),
              tgt: asResponse.encrypted_tgt,
            };
            sessionStorage.setItem(
              TICKET_CACHE_KEY,
              JSON.stringify(cache_data)
            );
            setTgtObtained(true);
            toast.success("TGT obtained successfully");

            // Start new connection for LIST_SERVICES
            const ws2 = new WebSocket(KDC_URL);
            ws2.onopen = () => {
              ws2.send(JSON.stringify({ type: "LIST_SERVICES" }));
            };
            ws2.onmessage = (event) => {
              try {
                const response = JSON.parse(event.data);
                if (response.services && Array.isArray(response.services)) {
                  setServices(response.services);
                }
              } catch {
                // ignore
              }
              ws2.close();
            };
            ws2.onerror = () => {};
            setTimeout(() => ws2.close(), 5000);
          } catch (error) {
            toast.error(`Failed to decrypt session key: ${error}`);
          }
        } else {
          toast.error(`Authentication failed: ${asResponse.message}`);
        }
      }
    };

    ws.onerror = () => {
      toast.error("Failed to connect to KDC");
    };

    // Timeout after 10 seconds
    setTimeout(() => {
      ws.close();
    }, 10000);
  };

  useEffect(() => {
    if (!user) return;

    // Check if TGT is cached
    const cached = sessionStorage.getItem(TICKET_CACHE_KEY);
    if (cached) {
      setTgtObtained(true);
    }

    // Always try to list services
    listServices();
  }, [user, listServices]);

  const requestServiceTicket = async (service: {
    name: string;
    url: string;
    description: string;
    principal_name: string;
  }) => {
    const cacheStr = sessionStorage.getItem(TICKET_CACHE_KEY);
    if (!cacheStr) {
      toast.error("No TGT cached");
      return;
    }
    const cache = JSON.parse(cacheStr);
    const tgt = cache.tgt;
    const as_session_key = Uint8Array.from(atob(cache.as_session_key), (c) =>
      c.charCodeAt(0)
    );

    const auth_timestamp = new Date().toISOString();
    const authenticator_data = {
      principal: `${user!.username}@MYKERBEROSPROJECT`,
      timestamp: auth_timestamp,
    };
    const authenticator_json = JSON.stringify(
      authenticator_data,
      Object.keys(authenticator_data).sort()
    );

    // Encrypt authenticator with AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
      "raw",
      as_session_key,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const encrypted_authenticator = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(authenticator_json)
    );
    const encrypted = new Uint8Array(
      iv.length + encrypted_authenticator.byteLength
    );
    encrypted.set(iv);
    encrypted.set(new Uint8Array(encrypted_authenticator), iv.length);
    const encrypted_authenticator_b64 = btoa(String.fromCharCode(...encrypted));

    const service_principal = service.principal_name;
    const tgs_req_data = {
      type: "TGS_REQ",
      tgt,
      authenticator: encrypted_authenticator_b64,
      service_principal,
    };

    const ws = new WebSocket(KDC_URL);
    ws.onopen = () => {
      ws.send(JSON.stringify(tgs_req_data));
    };
    ws.onmessage = async (event) => {
      try {
        const response = JSON.parse(event.data);
        if (response.status === "OK") {
          const encrypted_key_b64 = response.encrypted_service_session_key;
          const encrypted_key_bytes = Uint8Array.from(
            atob(encrypted_key_b64),
            (c) => c.charCodeAt(0)
          );
          const iv2 = encrypted_key_bytes.slice(0, 12);
          const ciphertext = encrypted_key_bytes.slice(12);
          const key2 = await crypto.subtle.importKey(
            "raw",
            as_session_key,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );
          const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv2 },
            key2,
            ciphertext
          );
          const service_session_key_data = JSON.parse(
            new TextDecoder().decode(decrypted)
          );
          const service_session_key_b64 =
            service_session_key_data.service_session_key;

          cache.service_ticket = response.service_ticket;
          cache.service_session_key = service_session_key_b64;
          sessionStorage.setItem(TICKET_CACHE_KEY, JSON.stringify(cache));

          setServiceKeys((prev) => ({
            ...prev,
            [service.name]: service_session_key_b64,
          }));
          toast.success(`Service ticket obtained for ${service.name}`);
        } else {
          toast.error(`TGS request failed: ${response.message}`);
        }
      } catch (error) {
        toast.error(`Error processing response: ${error}`);
      }
      ws.close();
    };
    ws.onerror = () => {
      toast.error("Failed to connect to KDC");
    };
    setTimeout(() => ws.close(), 10000);
  };

  return {
    tgtObtained,
    services,
    serviceKeys,
    getTGT,
    requestServiceTicket,
  };
}
