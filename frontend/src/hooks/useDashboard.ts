import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./useAuth";
import { toast } from "react-toastify";

const CA_URL = (import.meta as unknown as { env?: Record<string, string> }).env
  ?.VITE_CA_URL;

interface PendingRequest {
  request_id: string;
  new_cert_subject: string;
  created_at: string;
}

export function useDashboard() {
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
      toast.error(errorData.error || "Failed to approve request");
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
      toast.error(errorData.error || "Failed to reject request");
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

  return {
    user,
    pendingRequests,
    showNotifications,
    setShowNotifications,
    approveRequest,
    rejectRequest,
    handleLogout,
  };
}
