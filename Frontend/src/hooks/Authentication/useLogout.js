import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { toast } from "react-toastify";
import AxiosInstance from "../../utils/api-handler";

const useLogout = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    const refresh = localStorage.getItem("refresh_token");
    const res = await AxiosInstance.post("logout/", {
      refresh_token: refresh,
    });
    if (res.status === 204) {
      console.log("User logged out");
      logout();
      navigate("/");
      toast.warn("Logout successful");
    }
  };

  return handleLogout;
};

export default useLogout;
