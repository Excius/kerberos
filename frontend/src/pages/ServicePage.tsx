import { useParams, useNavigate } from "react-router-dom";
import { useService } from "../hooks/useService";
import { ArrowLeft } from "lucide-react";
import { useState } from "react";

export default function ServicePage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { services, serviceKeys, requestServiceTicket } = useService();
  const [serviceResponse, setServiceResponse] = useState<Record<
    string,
    unknown
  > | null>(null);

  const service = services.find((s) => s.name === name);

  if (!service) {
    return (
      <div className="min-h-screen bg-linear-to-br from-slate-50 via-blue-50 to-slate-100 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900 mb-4">
            Service Not Found
          </h1>
          <button
            onClick={() => navigate("/dashboard")}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  const accessService = async () => {
    const cacheStr = sessionStorage.getItem("kerberos_tgt_cache");
    if (!cacheStr) {
      alert("No service ticket cached");
      return;
    }
    const cache = JSON.parse(cacheStr);
    const serviceTicket = cache.service_ticket;
    const serviceSessionKey = Uint8Array.from(
      atob(cache.service_session_key),
      (c) => c.charCodeAt(0)
    );

    const authTimestamp = new Date().toISOString();
    const userStr = localStorage.getItem("auth_user");
    if (!userStr) {
      alert("User not logged in");
      return;
    }
    const user = JSON.parse(userStr);
    const authenticatorData = {
      principal: `${user.username}@MYKERBEROSPROJECT`,
      timestamp: authTimestamp,
    };
    const authenticatorJson = JSON.stringify(
      authenticatorData,
      Object.keys(authenticatorData).sort()
    );

    // Encrypt authenticator with AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
      "raw",
      serviceSessionKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const encryptedAuthenticator = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(authenticatorJson)
    );
    const encrypted = new Uint8Array(
      iv.length + encryptedAuthenticator.byteLength
    );
    encrypted.set(iv);
    encrypted.set(new Uint8Array(encryptedAuthenticator), iv.length);
    const encryptedAuthenticatorB64 = btoa(String.fromCharCode(...encrypted));

    const apReqData = {
      type: "AP_REQ",
      service_ticket: serviceTicket,
      authenticator: encryptedAuthenticatorB64,
    };

    // Send to service URL (convert http to ws for WebSocket)
    const wsUrl = service.url.replace(/^http/, "ws");
    try {
      const ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        ws.send(JSON.stringify(apReqData));
      };
      ws.onmessage = (event) => {
        try {
          const response = JSON.parse(event.data);
          setServiceResponse(response);
        } catch {
          setServiceResponse({ error: "Failed to parse response" });
        }
        ws.close();
      };
      ws.onerror = () => {
        setServiceResponse({ error: "Failed to connect to service server" });
      };
      setTimeout(() => ws.close(), 10000);
    } catch (e) {
      console.error("WebSocket connection failed:", e);
    }
  };

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-50 via-blue-50 to-slate-100">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <button
          onClick={() => navigate("/dashboard")}
          className="flex items-center space-x-2 text-blue-600 hover:text-blue-700 mb-6"
        >
          <ArrowLeft className="w-5 h-5" />
          <span>Back to Dashboard</span>
        </button>

        <div className="bg-white rounded-2xl shadow-xl p-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            {service.name}
          </h1>
          <p className="text-gray-600 text-lg mb-6">{service.description}</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                Service Details
              </h3>
              <div className="space-y-2">
                <p className="text-sm text-gray-600">
                  <span className="font-medium">URL:</span> {service.url}
                </p>
                <p className="text-sm text-gray-600">
                  <span className="font-medium">Principal:</span>{" "}
                  {service.principal_name}
                </p>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                Connection Status
              </h3>
              {serviceKeys[service.name] ? (
                <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                  <p className="text-sm text-green-800 font-medium">
                    Connected
                  </p>
                  <p className="text-xs text-green-700 mt-1">
                    Service Key: {serviceKeys[service.name]}
                  </p>
                  <button
                    onClick={accessService}
                    className="mt-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded transition-colors"
                  >
                    Access Service
                  </button>
                </div>
              ) : (
                <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                  <p className="text-sm text-gray-800">Not Connected</p>
                  <button
                    onClick={() => requestServiceTicket(service)}
                    className="mt-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
                  >
                    Connect to Service
                  </button>
                </div>
              )}
            </div>
          </div>

          {serviceResponse && (
            <div className="mt-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                Service Response
              </h3>
              <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                <pre className="text-sm text-gray-800 whitespace-pre-wrap">
                  {JSON.stringify(serviceResponse, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
