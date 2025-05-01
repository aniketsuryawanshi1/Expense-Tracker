import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext"; // Adjust path as needed
import PropTypes from "prop-types";

const PrivateRoute = ({ children }) => {
  const { token } = useAuth();

  return token ? children : <Navigate to="/login" replace />;
};

PrivateRoute.propTypes = {
  children: PropTypes.node.isRequired,
};

export default PrivateRoute;
