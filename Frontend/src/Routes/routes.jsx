import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { Layout } from "antd";
import {
  Register,
  Login,
  EmailVerification,
  Dashboard,
  RequestAction,
  SetNewPassword,
  LandingPage,
} from "../Pages/index";
import { Navbar, SideNav } from "../components/index";

const { Content } = Layout;

const MainRoutes = () => {
  return (
    <Router>
      <Layout style={{ minHeight: "100vh", width: "100vw" }}>
        <Navbar /> {/* Top Navbar */}
        <Layout>
          <SideNav /> {/* Side Navigation */}
          <Layout style={{ paddingLeft: 200 }}>
            {" "}
            {/* Adjust padding for Sider */}
            <Content
              style={{
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                padding: "24px",
              }}
            >
              <Routes>
                <Route path="/" element={<LandingPage />} />{" "}
                {/* Landing Page */}
                <Route path="/register" element={<Register />} />
                <Route path="/login" element={<Login />} />
                <Route path="/verify-email" element={<EmailVerification />} />
                <Route path="/resend-otp" element={<RequestAction />} />
                <Route path="/password-reset" element={<RequestAction />} />
                <Route
                  path="/api/password-reset-confirm/:uidb64/:token"
                  element={<SetNewPassword />}
                />
                <Route path="/dashboard" element={<Dashboard />} />
              </Routes>
            </Content>
          </Layout>
        </Layout>
      </Layout>
    </Router>
  );
};

export default MainRoutes;
