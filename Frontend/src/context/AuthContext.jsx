import { createContext, useContext, useState, useEffect } from "react";
import PropTypes from "prop-types";

// Create context object.
const AuthContext = createContext();

// AuthProvider component wraps the entire app to provide auth state.
export const AuthProvider = ({ children }) => {
  // Create a state to store token.
  const [token, setToken] = useState(null);

  // Load token from LocalStorage once when the apps loads.
  useEffect(() => {
    // get token from local storage.
    const storedToken = localStorage.getItem("token");

    // If token is exists, set it in state.
    if (storedToken) setToken(storedToken);
  }, []); // Empty array ensures this runs only once on mount

  // Function to login the user : save token in localstorage and update state.
  const login = (newToken) => {
    localStorage.setItem("token", newToken); // Save the token in localstorage.
    setToken(newToken); // Update the token in state.
  };

  // Logout function : make an api call and clears localstorage and context state.
  const logout = () => {
    // Clear all tokens and user data
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user");
    localStorage.removeItem("token");
    setToken(null);
  };

  // Return the context provider with token, login and logout functions.
  return (
    <AuthContext.Provider value={{ token, login, logout }}>
      {children}
      {/* Render the child component. */}
    </AuthContext.Provider>
  );
};

AuthProvider.propTypes = {
  children: PropTypes.node.isRequired,
};

export const useAuth = () => useContext(AuthContext);
