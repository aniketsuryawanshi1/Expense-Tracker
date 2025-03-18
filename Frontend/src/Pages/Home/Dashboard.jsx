import { CustomButton } from '../../components/index';
import { LogoutOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import AxiosInstance from "../../utils/api-handler"
const Dashboard = () => {

    const navigate = useNavigate();

    // Get user data from local storage and check if it exists. If not, redirect to login page.
    const data = JSON.parse(localStorage.getItem("user"));

    // If user data does not exist, redirect to login page.
    if (!data) {
        navigate("/");
        return null;
    }

    // Logout user function using axios instance.
    const handleLogout = async () => {
        const refresh = localStorage.getItem("refresh_token");
        const res = await AxiosInstance.post("logout/", {
          refresh_token: refresh,
        });
        if (res.status === 204) {
            console.log("User logged out");
          localStorage.clear();
          navigate("/");
          toast.warn("Logout successful");
        }
      };


  return (
    <div>
        <h1>Dashboard</h1>

        <div>
            <div style={
                {
                    padding: "20px",
                    border: "1px solid #ccc",
                    borderRadius: "5px",
                    marginBottom: "20px",
                    width: "100%",
                    maxWidth: "400px",
                    textAlign: "center",
                    boxShadow: "0px 0px 10px rgba(0,0,0,0.2)"
                }
            }>
                <h3>
                    Welcome : {data.username}
                    Email : {data.email}

                </h3>
            </div>
            {/* Logout user. */}
            <CustomButton 
            style={
                {
                    backgroundColor: "red",
                    color: "white",
                    with:"100%",
                    maxWidth: "200px",
                }
            }
            icon={<LogoutOutlined />}
            onClick={handleLogout}>
                Logout
            </CustomButton>
        </div>
    </div>
  )
}

export default Dashboard