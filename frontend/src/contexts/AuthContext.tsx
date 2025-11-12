import { createContext, useState, useEffect, useCallback } from "react";
import type { ReactNode } from "react";
import { generateKeyPair, generateCSR, loadStoredKeyPair } from "../lib/crypto";

// Read CA URL from Vite env
const CA_URL: string | undefined = (
  import.meta as unknown as { env?: Record<string, string> }
).env?.VITE_CA_URL;

interface User {
  id: string;
  username: string;
  certificate: string;
}

interface AuthContextType {
  user: User | null;
  keyPair: CryptoKeyPair | null;
  loading: boolean;
  pendingRequestId: string | null;
  signup: (username: string, password: string) => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

// eslint-disable-next-line react-refresh/only-export-components
export const AuthContext = createContext<AuthContextType | undefined>(
  undefined
);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingRequestId, setPendingRequestId] = useState<string | null>(null);

  const startPolling = useCallback(
    async (requestId: string, username: string, password: string) => {
      const poll = async (): Promise<void> => {
        try {
          const pollResp = await fetch(
            `${CA_URL}/check-request-status/${requestId}`
          );
          const pollData = await pollResp.json();

          if (
            pollResp.status === 200 &&
            pollData.status === "approved" &&
            pollData.certificate
          ) {
            const certificatePem = pollData.certificate as string;
            localStorage.setItem(`kerberos:cert:${username}`, certificatePem);
            localStorage.removeItem(`kerberos:pending:${username}`);

            const keyPair = await generateKeyPair({
              password,
              persist: true,
              username,
            });

            const authenticatedUser = {
              id: `local-${username}-${Date.now()}`,
              username,
              certificate: certificatePem,
            };

            setUser(authenticatedUser);
            setKeyPair(keyPair);
            localStorage.setItem(
              "auth_user",
              JSON.stringify(authenticatedUser)
            );
            setPendingRequestId(null);
          } else if (pollData.status === "pending_approval") {
            setTimeout(poll, 5000);
          } else {
            setPendingRequestId(null);
            localStorage.removeItem(`kerberos:pending:${username}`);
          }
        } catch {
          setPendingRequestId(null);
          localStorage.removeItem(`kerberos:pending:${username}`);
        }
      };

      poll();
    },
    []
  );

  useEffect(() => {
    // No auto-login; always require manual login
    setLoading(false);
  }, []);

  const signup = async (username: string, password: string) => {
    const keyPairStored = localStorage.getItem(`kerberos:keypair:${username}`);
    const certStored = localStorage.getItem(`kerberos:cert:${username}`);
    if (keyPairStored || certStored) {
      throw new Error(
        "User already registered on this device. Please login instead."
      );
    }

    const keyPair = await generateKeyPair({
      password,
      persist: true,
      username,
    });
    const csrPem = await generateCSR(username, keyPair);

    if (!CA_URL) {
      throw new Error("CA_URL is not configured. Set VITE_CA_URL in your env.");
    }

    try {
      // Submit CSR to CA
      const resp = await fetch(`${CA_URL}/submit-csr`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          principal_name: username,
          csr_pem: csrPem,
          is_signup: true,
        }),
      });

      let certificatePem: string | null = null;
      let requestId: string | undefined;
      let respData: Record<string, unknown> | null = null;
      try {
        respData = await resp.json();
      } catch {
        // ignore JSON parse errors
      }

      if (resp.status === 201 && respData?.certificate) {
        certificatePem = respData.certificate as string;
        // Persist certificate locally on the user's machine
        try {
          localStorage.setItem(`kerberos:cert:${username}`, certificatePem);
        } catch {
          // ignore storage errors (private mode/quota)
        }
        // Optionally offer a download to the user
        try {
          const blob = new Blob([certificatePem], {
            type: "application/x-pem-file",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `${username}.crt.pem`;
          a.click();
          URL.revokeObjectURL(url);
        } catch {
          // non-JSON response; leave respData as null
        }
      } else if (resp.status === 202 && respData?.request_id) {
        requestId = respData.request_id as string;
        localStorage.setItem(`kerberos:pending:${username}`, requestId);
        setPendingRequestId(requestId);
        startPolling(requestId, username, password);
      } else if (resp.status === 409) {
        const msg = String(respData?.error || "User already exists.");
        throw new Error(msg);
      } else if (!resp.ok) {
        throw new Error(`CA error ${resp.status}: ${resp.statusText}`);
      }

      // If we have a certificate, consider the user authenticated
      if (certificatePem) {
        const newUser = {
          id: `local-${username}-${Date.now()}`, // Generate a local unique ID
          username,
          certificate: certificatePem,
        };
        setUser(newUser);
        setKeyPair(keyPair);
        localStorage.setItem("auth_user", JSON.stringify(newUser));
      }
    } catch (error) {
      localStorage.removeItem(`kerberos:keypair:${username}`);
      throw error;
    }
  };

  const login = async (username: string, password: string) => {
    const keyPairStored = localStorage.getItem(`kerberos:keypair:${username}`);
    const pendingRequestIdStored = localStorage.getItem(
      `kerberos:pending:${username}`
    );

    if (pendingRequestIdStored && keyPairStored) {
      // Resume polling for existing pending request from localStorage
      setPendingRequestId(pendingRequestIdStored);
      startPolling(pendingRequestIdStored, username, password);
      return;
    }

    if (pendingRequestId && !keyPairStored) {
      // Resume polling for existing pending request
      setPendingRequestId(pendingRequestId);
      startPolling(pendingRequestId, username, password);
      return;
    }

    if (keyPairStored) {
      // Existing user/device: verify password and check certificate
      const loadedKeyPair = await loadStoredKeyPair(username, password);
      if (!loadedKeyPair) {
        throw new Error("Invalid password");
      }

      setKeyPair(loadedKeyPair);

      const certificate = localStorage.getItem(`kerberos:cert:${username}`);
      if (!certificate) {
        throw new Error("No certificate found. Please contact support.");
      }

      const authenticatedUser = {
        id: `local-${username}-${Date.now()}`,
        username,
        certificate,
      };

      setUser(authenticatedUser);
      localStorage.setItem("auth_user", JSON.stringify(authenticatedUser));
    } else {
      // New device: generate keys, send CSR, poll for approval
      const keyPair = await generateKeyPair({
        password,
        persist: true,
        username,
      });
      const csrPem = await generateCSR(username, keyPair);

      if (!CA_URL) {
        throw new Error("CA_URL is not configured.");
      }

      try {
        const resp = await fetch(`${CA_URL}/submit-csr`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            principal_name: username,
            csr_pem: csrPem,
            is_signup: false,
          }),
        });

        let respData: Record<string, unknown> | null = null;
        try {
          respData = await resp.json();
        } catch {
          // ignore
        }

        if (resp.status === 409) {
          const msg = String("User not found. Please signup first.");
          throw new Error(msg);
        }

        if (resp.status === 202 && respData?.request_id) {
          const requestId = respData.request_id as string;
          localStorage.setItem(`kerberos:pending:${username}`, requestId);
          setPendingRequestId(requestId);
          startPolling(requestId, username, password);
        } else if (resp.status === 201 && respData?.certificate) {
          // In case CA approves immediately (though for new devices it should be 202)
          const certificatePem = respData.certificate as string;
          localStorage.setItem(`kerberos:cert:${username}`, certificatePem);

          const authenticatedUser = {
            id: `local-${username}-${Date.now()}`,
            username,
            certificate: certificatePem,
          };

          setUser(authenticatedUser);
          localStorage.setItem("auth_user", JSON.stringify(authenticatedUser));
        } else {
          const msg = String(respData?.error || `CA error ${resp.status}`);
          throw new Error(msg);
        }
      } catch (error) {
        localStorage.removeItem(`kerberos:keypair:${username}`);
        throw error;
      }
    }
  };

  const logout = () => {
    setUser(null);
    setKeyPair(null);
    localStorage.removeItem("auth_user");
    sessionStorage.removeItem("kerberos_tgt_cache");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        keyPair,
        loading,
        pendingRequestId,
        signup,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
