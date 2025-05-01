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
  GenerateReport,
  AddNew,
  AddCategory,
} from "../Pages/index";

import { Navbar, SideNav } from "../components/index";
import { useAuth } from "../context/AuthContext";
import PrivateRoute from "./ProtectedRoute";
import PublicRoutes from "./PublicRoutes";
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
              <Route
                path="/"
                element={
                  <PublicRoutes>
                    <LandingPage />
                  </PublicRoutes>
                }
              />
              <Route
                path="/register"
                element={
                  <PublicRoutes>
                    <Register />
                  </PublicRoutes>
                }
              />
              <Route
                path="/login"
                element={
                  <PublicRoutes>
                    <Login />
                  </PublicRoutes>
                }
              />
              <Route
                path="/verify-email"
                element={
                  <PublicRoutes>
                    <EmailVerification />
                  </PublicRoutes>
                }
              />
              <Route
                path="/resend-otp"
                element={
                  <PublicRoutes>
                    <EmailVerification />
                  </PublicRoutes>
                }
              />
              <Route
                path="/password-reset"
                element={
                  <PublicRoutes>
                    <RequestAction />
                  </PublicRoutes>
                }
              />
              <Route
                path="/api/password-reset-confirm/:uidb64/:token"
                element={
                  <PublicRoutes>
                    <SetNewPassword />
                  </PublicRoutes>
                }
              />

              <Route
                path="/dashboard"
                element={
                  <PrivateRoute>
                    <Dashboard />
                  </PrivateRoute>
                }
              />
              <Route
                path="/generatereport"
                element={
                  <PrivateRoute>
                    <GenerateReport />
                  </PrivateRoute>
                }
              />
              <Route
                path="/addnew"
                element={
                  <PrivateRoute>
                    <AddNew />
                  </PrivateRoute>
                }
              />
              <Route
                path="/addcategory"
                element={
                  <PrivateRoute>
                    <AddCategory />
                  </PrivateRoute>
                }
              />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </Layout>
  );
};

export default MainRoutes;
