import { useState } from "react";
import { axios } from "axios";
import { useNavigate } from "react-router-dom";
import BASE_URL from "../../utils/urls";
import { toast } from "react-toastify";
const useRegister = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const [registerData, setRegisterData] = useState({
    email: "",
    username: "",
    password: "",
    password2: "",
  });

  const [error, setError] = useState(" ");

  const handleOnChange = (e) => {
    setRegisterData({ ...registerData, [e.target.name]: e.target.value });
  };

  const handleOnSubmit = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);
      const response = await axios.post(
        `${BASE_URL}/register/`,registerData
      );
      if(response.status == 201){
        navigate("/verify-email");
        toast.success("Registration successful, Please verify your email");
      }
    }
    catch (error) {
      if(error.response){
        setError(error.response.data.message);
        setLoading(false);
      }
    }
    
  };

  return {
    handleOnChange,
    handleOnSubmit,
    registerData,
    loading,
    error,
  };
};

export default useRegister;
