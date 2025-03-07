import { useState } from "react";
import AxiosInstance from "../../utils/api-handler";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";

const useLogin = () => {
  const navigate = useNavigate(); // Navigation hook
  const [loading, setLoading] = useState(false);
  const [loginData, setLoginData] = useState({
    email: "",
    password: "",
  });

  // Function to handle input changes
  const handleChange = (e) => {
    setLoginData({ ...loginData, [e.target.name]: e.target.value });
  };

  // Handle form submission
  const handleOnSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await AxiosInstance.post("login/", loginData);

      if (response.status === 200) {
        const responseData = response.data;

        const user = {
          username: responseData.username,
          email: responseData.email,
        };

        // Store tokens & user data
        localStorage.setItem("token", responseData.access_token);
        localStorage.setItem("refresh_token", responseData.refresh_token);
        localStorage.setItem("user", JSON.stringify(user));

        navigate("/dashboard");
        toast.success("Login Successful");
      } else {
        toast.error("Login failed! Please try again.");
      }
    } catch (error) {
      const errorMessage =
        error.response?.data?.message || "Something went wrong, Login Failed..!";
      toast.error(errorMessage);
      console.error("Login Failed:", errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return {
    loginData,
    handleChange,
    handleOnSubmit,
    loading,
  };
};

export default useLogin;
