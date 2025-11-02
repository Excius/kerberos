import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { Bell, LogOut, X, Check } from "lucide-react";

const CA_URL = (import.meta as unknown as { env?: Record<string, string> }).env
  ?.VITE_CA_URL;

interface PendingRequest {
  request_id: string;
  new_cert_subject: string;
  created_at: string;
}

export default function Dashboard() {
  const { user, keyPair, logout } = useAuth();
  const navigate = useNavigate();
  const [pendingRequests, setPendingRequests] = useState<PendingRequest[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);

  const pollPendingRequests = useCallback(async () => {
    if (!user || !keyPair || !CA_URL) return;

    const timestamp = new Date().toISOString();
    const data = new TextEncoder().encode(timestamp);
    const signature = await window.crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      keyPair.privateKey,
      data
    );
    const signatureB64 = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    );

    const resp = await fetch(`${CA_URL}/poll-pending-requests`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-Cert": btoa(user.certificate),
        "X-Client-Signature": signatureB64,
        "X-Client-Timestamp": timestamp,
      },
    });

    if (resp.ok) {
      const data = await resp.json();
      if (data.pending_requests) {
        setPendingRequests(data.pending_requests);
      }
    }
  }, [user, keyPair]);

  const approveRequest = async (requestId: string) => {
    if (!user || !keyPair || !CA_URL) return;

    const timestamp = new Date().toISOString();
    const data = new TextEncoder().encode(timestamp);
    const signature = await window.crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      keyPair.privateKey,
      data
    );
    const signatureB64 = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    );

    const resp = await fetch(`${CA_URL}/approve-request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-Cert": btoa(user.certificate),
        "X-Client-Signature": signatureB64,
        "X-Client-Timestamp": timestamp,
      },
      body: JSON.stringify({ request_id: requestId }),
    });

    if (resp.ok) {
      const data = await resp.json();
      if (data.status === "approved") {
        setPendingRequests((prev) =>
          prev.filter((r) => r.request_id !== requestId)
        );
      }
    } else {
      const errorData = await resp.json().catch(() => ({}));
      alert(errorData.error || "Failed to approve request");
    }
  };

  const rejectRequest = async (requestId: string) => {
    if (!user || !keyPair || !CA_URL) return;

    const timestamp = new Date().toISOString();
    const data = new TextEncoder().encode(timestamp);
    const signature = await window.crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      keyPair.privateKey,
      data
    );
    const signatureB64 = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    );

    const resp = await fetch(`${CA_URL}/approve-request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-Cert": btoa(user.certificate),
        "X-Client-Signature": signatureB64,
        "X-Client-Timestamp": timestamp,
      },
      body: JSON.stringify({ request_id: requestId, action: "reject" }),
    });

    if (resp.ok) {
      const data = await resp.json();
      if (data.status === "rejected") {
        setPendingRequests((prev) =>
          prev.filter((r) => r.request_id !== requestId)
        );
      }
    } else {
      const errorData = await resp.json().catch(() => ({}));
      alert(errorData.error || "Failed to reject request");
    }
  };

  useEffect(() => {
    if (!user) {
      navigate("/login");
      return;
    }

    // Initial poll
    pollPendingRequests();

    // Poll every 30 seconds
    const interval = setInterval(pollPendingRequests, 30000);

    return () => clearInterval(interval);
  }, [user, navigate, pollPendingRequests]);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-50 via-blue-50 to-slate-100">
      <nav className="bg-white shadow-md border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-lg">
                  {user?.username.charAt(0).toUpperCase()}
                </span>
              </div>
              <span className="text-lg font-semibold text-gray-900">
                {user?.username}
              </span>
            </div>

            <div className="flex items-center space-x-4">
              <div className="relative">
                <button
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="relative p-2 rounded-lg hover:bg-gray-100 transition-colors duration-200"
                >
                  <Bell className="w-6 h-6 text-gray-700" />
                  {pendingRequests.length > 0 && (
                    <span className="absolute top-0 right-0 inline-flex items-center justify-center w-5 h-5 text-xs font-bold text-white bg-red-500 rounded-full">
                      {pendingRequests.length}
                    </span>
                  )}
                </button>

                {showNotifications && (
                  <div className="absolute right-0 mt-2 w-96 bg-white rounded-lg shadow-2xl border border-gray-200 z-50 animate-fade-in">
                    <div className="p-4 border-b border-gray-200 flex justify-between items-center">
                      <h3 className="text-lg font-semibold text-gray-900">
                        Pending Requests
                      </h3>
                      <button
                        onClick={() => setShowNotifications(false)}
                        className="p-1 hover:bg-gray-100 rounded transition-colors"
                      >
                        <X className="w-5 h-5 text-gray-500" />
                      </button>
                    </div>
                    <div className="max-h-96 overflow-y-auto">
                      {pendingRequests.length === 0 ? (
                        <div className="p-8 text-center text-gray-500">
                          <Bell className="w-12 h-12 mx-auto mb-2 text-gray-300" />
                          <p>No pending requests</p>
                        </div>
                      ) : (
                        pendingRequests.map((request) => (
                          <div
                            key={request.request_id}
                            className="p-4 border-b border-gray-100 hover:bg-gray-50 transition-colors"
                          >
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <p className="text-sm text-gray-800">
                                  New device request for{" "}
                                  {request.new_cert_subject}
                                </p>
                                <p className="text-xs text-gray-500 mt-1">
                                  {new Date(request.created_at).toLocaleString()}
                                </p>
                              </div>
                              <div className="flex space-x-2 ml-4">
                                <button
                                  onClick={() => approveRequest(request.request_id)}
                                  className="flex items-center space-x-1 px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-xs rounded transition-colors"
                                >
                                  <Check className="w-3 h-3" />
                                  <span>Approve</span>
                                </button>
                                <button
                                  onClick={() => rejectRequest(request.request_id)}
                                  className="flex items-center space-x-1 px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
                                >
                                  <X className="w-3 h-3" />
                                  <span>Reject</span>
                                </button>
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>

              <button
                onClick={handleLogout}
                className="flex items-center space-x-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-all duration-200 transform hover:scale-105 active:scale-95 shadow-md hover:shadow-lg"
              >
                <LogOut className="w-4 h-4" />
                <span className="font-medium">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="bg-white rounded-2xl shadow-xl p-12 min-h-[500px] relative overflow-hidden">
          <div className="absolute inset-0 bg-linear-to-br from-blue-50/50 via-transparent to-slate-50/50"></div>
          <div className="relative z-10">
            <h1 className="text-4xl font-bold text-gray-900 mb-4">Dashboard</h1>
            <p className="text-gray-600 text-lg">
              Welcome to your secure dashboard, {user?.username}!
            </p>
            <div className="mt-8 p-6 bg-blue-50 border border-blue-200 rounded-lg">
              <h2 className="text-lg font-semibold text-blue-900 mb-2">
                Certificate-Based Authentication Active
              </h2>
              <p className="text-blue-700 text-sm">
                Your account is secured with asymmetric key pairs and a valid
                certificate issued by the CA. You can approve pending device
                requests from the notification bell.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
