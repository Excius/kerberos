import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { useAuth } from "./hooks/useAuth";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Dashboard from "./pages/Dashboard";
import ServicePage from "./pages/ServicePage";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

function PendingModal() {
  const { pendingRequestId } = useAuth();
  if (!pendingRequestId) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg shadow-lg max-w-md w-full mx-4">
        <h2 className="text-xl font-semibold mb-4">
          Device Verification Required
        </h2>
        <p className="text-gray-700 mb-4">
          Please verify yourself from your other trusted device. The request is
          being processed in the background.
        </p>
        <p className="text-sm text-gray-500 mb-4">
          Request ID: {pendingRequestId}
        </p>
        <div className="flex justify-end">
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-800 rounded-lg transition-colors"
          >
            Back to Login
          </button>
        </div>
      </div>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <PendingModal />
        <Routes>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/service/:name"
            element={
              <ProtectedRoute>
                <ServicePage />
              </ProtectedRoute>
            }
          />
        </Routes>
        <ToastContainer />
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
