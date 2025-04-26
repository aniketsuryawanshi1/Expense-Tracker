import { Routes, Route } from "react-router-dom";
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
import { useAuth } from "../context/AuthContext";
const { Content } = Layout;

const MainRoutes = () => {
  // use shared context.
  const { token } = useAuth();

  return (
    <Layout style={{ minHeight: "100vh", width: "100vw" }}>
      <Navbar />
      <Layout>
        {token && <SideNav />} {/* Show SideNav only if logged in */}
        <Layout style={{ paddingLeft: token ? 0 : 0 }}>
          <Content
            style={{
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              padding: "10px",
            }}
          >
            <Routes>
              <Route path="/" element={<LandingPage />} />
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
  );
};

export default MainRoutes;
