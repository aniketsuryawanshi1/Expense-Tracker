import { CustomButton } from "../../components/index";
import { LogoutOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { useAuth } from "../../context/AuthContext";
import useLogout from "../../hooks/Authentication/useLogout";
const Dashboard = () => {
  const navigate = useNavigate();
  const handleLogout = useLogout();

  // Get token and logout from context.
  const { token } = useAuth();

  // Get user data from local storage and check if it exists. If not, redirect to login page.
  const data = JSON.parse(localStorage.getItem("user"));

  // If no token or user data, redirect to login page.
  useEffect(() => {
    if (!token || !data) {
      navigate("/");
    }
  }, [token, data, navigate]);
  if (!data) {
    return null;
  }
  return (
    <div>
      <h1>Dashboard</h1>

      <div>
        <div
          style={{
            padding: "20px",
            border: "1px solid #ccc",
            borderRadius: "5px",
            marginBottom: "20px",
            width: "100%",
            maxWidth: "400px",
            textAlign: "center",
            boxShadow: "0px 0px 10px rgba(0,0,0,0.2)",
          }}
        >
          <h3>
            Welcome : {data.username} <br />
            Email : {data.email}
          </h3>
        </div>
        {/* Logout user. */}
        <CustomButton
          style={{
            backgroundColor: "red",
            color: "white",
            with: "100%",
            maxWidth: "200px",
          }}
          icon={<LogoutOutlined />}
          onClick={handleLogout}
        >
          Logout
        </CustomButton>
      </div>
    </div>
  );
};

export default Dashboard;
