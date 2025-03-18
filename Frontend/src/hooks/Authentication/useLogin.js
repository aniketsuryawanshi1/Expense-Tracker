import { useState } from "react";
import AxiosInstance from "../../utils/api-handler";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";

const useLogin = () => {
  const navigate = useNavigate(); // Navigation hook
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");



  // Handle form submission
  const handleOnSubmit = async (formData, resetForm) => {
    try {
      setLoading(true);
      console.log("API Request Data:", formData); // ✅ Debugging
      const response = await AxiosInstance.post("login/", formData);
      console.log("after login api call.")
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

        toast.success("You have successfully logged in.")
        resetForm();
        navigate("/dashboard");

        
      } 
    } catch (err) {
      console.error("API Error : ", err.response?.data || err.message);
      setError(err.response?.data?.message || "Something went wrong");
      toast.error(err.response?.data?.message || "Login Failed.");
    } finally {
      setLoading(false);
    }
  };

  return {

    handleOnSubmit,
    loading,
    error,
  };
};

export default useLogin;
