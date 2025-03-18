import { useState } from "react";
import AxiosInstance from "../../utils/api-handler";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";

const useRegister = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleOnSubmit = async (formData, resetForm) => {
    try {
      setLoading(true);
      console.log("API Request Data:", formData); // ✅ Debugging

      const response = await AxiosInstance.post("/register/", formData);
      console.log("API Endpoint Path:", response.config.url); // ✅ Debugging

      if (response.status === 201) {
        toast.success("Registration Successful! Please verify your email.");
        resetForm(); // Reset form on success
        navigate("/verify-email");
      }
    } catch (err) {
      console.error("API Error:", err.response?.data || err.message);
      setError(err.response?.data?.message || "Something went wrong");
      toast.error(err.response?.data?.message || "Registration Failed");
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

export default useRegister;
