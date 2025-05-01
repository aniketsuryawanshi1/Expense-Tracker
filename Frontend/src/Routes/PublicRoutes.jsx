// src/routes/PublicRoutes.jsx
import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import PropTypes from "prop-types";
const PublicRoutes = ({ children }) => {
  const { token, loading } = useAuth();

  if (loading) return <div>Loading...</div>;

  // ✅ If token exists, redirect to dashboard
  if (token) {
    return <Navigate to="/dashboard" replace />;
  }

  PublicRoutes.propTypes = {
    children: PropTypes.node.isRequired,
  };

  return children;
};

export default PublicRoutes;
