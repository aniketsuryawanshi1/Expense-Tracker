import { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";

const useRegister = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleOnSubmit = async (formData) => {
    try {
      setLoading(true);
      console.log("API Request Data:", formData); // ✅ Debugging

      const response = await axios.post("http://localhost:8000/api/register/", formData);
      if (response.status === 201) {
        toast.success("Registration Successful! Please verify your email.");
        navigate("/verify-otp");
      }
    } catch (err) {
      console.error("API Error:", err.response?.data || err.message);
      setError(err.response?.data || "Something went wrong");
      toast.error("Registration Failed");
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
