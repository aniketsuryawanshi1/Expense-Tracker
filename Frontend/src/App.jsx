import { BrowserRouter as Router } from "react-router-dom";
import MainRoutes from "./Routes/routes";
import { AuthProvider } from "./context/AuthContext";
const App = () => {
  return (
    <Router>
      <AuthProvider>
        <MainRoutes />
      </AuthProvider>
    </Router>
  );
};

export default App;
