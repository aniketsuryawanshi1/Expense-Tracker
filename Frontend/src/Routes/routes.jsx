import {
  BrowserRouter as Router,
  Routes,
  Route,
  
} from "react-router-dom";
import { Layout } from "antd";
import { Register, Login, EmailVerification, Dashboard, RequestAction,SetNewPassword, LandingPage  } from "../Pages/index";
import { Navbar } from "../components/index";


const { Content } = Layout;

const MainRoutes = () => {


  return (
    <Router>
      <Layout
        style={{ minHeight: "100vh", width: "100vw" }} //, overflow: "hidden"
      >
        {/* Use Navbar inside Header */}
        
        <Navbar />
        <Content style={
          {
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
          }
        } >
          <Routes>
            <Route path="/" element={<LandingPage />} />  {/* Landing Page */}
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route path="/verify-email" element={<EmailVerification />} />
            <Route path="/resend-otp" element={<RequestAction />} />
            <Route path="/password-reset" element={<RequestAction />} /> 
            <Route path="/api/password-reset-confirm/:uidb64/:token" element={<SetNewPassword />} />  
            <Route path="/dashboard" element={<Dashboard />} />
          </Routes>
        </Content>

        {/* <Footer style={{ textAlign: "center", padding: "10px 0" }}>
          Footer Content
        </Footer> */}
      </Layout>
    </Router>
  );
};

export default MainRoutes;
