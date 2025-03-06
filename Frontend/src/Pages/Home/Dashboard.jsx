import { CustomButton } from '../../components/index';
import { LogoutOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import AxiosInstance from "../../utils/api-handler"
const Dashboard = () => {

    const navigate = useNavigate();

    
    // Logout user function using axios instance.
    const handleLogout = async () => {
        const refresh = JSON.parse(localStorage.getItem("refresh_token"));
        const res = await AxiosInstance.post("logout/", {
          refresh_token: refresh,
        });
        if (res.status === 204) {
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
                    Welcome : user.username

                    Email : user.email

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