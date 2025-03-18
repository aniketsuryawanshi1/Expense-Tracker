import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { Layout } from "antd";
import { Register, Login, EmailVerification, Dashboard, RequestAction,SetNewPassword  } from "../Pages/index";
import { Navbar } from "../components/index";
import { useState } from "react";


const { Content, Footer } = Layout;

const MainRoutes = () => {
  // State to manage theme mode
  const [theme, setTheme] = useState("light");

  // Function to toggle theme
  const handleThemeChange = () => {
    setTheme(theme === "light" ? "dark" : "light");
  };

  return (
    <Router>
      <Layout
        style={{ minHeight: "100vh", width: "100vw" }} //, overflow: "hidden"
      >
        {/* Use Navbar inside Header */}
        <Navbar onThemeChange={handleThemeChange} theme={theme} />

        <Content style={{ padding: "20px" }}>
          <Routes>
            <Route path="/" element={<Navigate to="/Login" />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route path="/verify-email" element={<EmailVerification />} />
            <Route path="/resend-otp" element={<RequestAction />} />
            <Route path="/password-reset" element={<RequestAction />} /> 
            <Route path="/set-new-password" element={<SetNewPassword />} />  
            <Route path="/dashboard" element={<Dashboard />} />
          </Routes>
        </Content>

        <Footer style={{ textAlign: "center", padding: "10px 0" }}>
          Footer Content
        </Footer>
      </Layout>
    </Router>
  );
};

export default MainRoutes;
