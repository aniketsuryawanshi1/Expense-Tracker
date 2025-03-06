import { useState } from 'react';
import AxiosInstance from '../../utils/api-handler';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';

const useLogin = () => {

    const navigate  =useNavigate(); // use for navigation after getting success api call.
    const [loading, setLoading] = useState(false); // use for loading state.
    const [loginData, setLoginData] = useState({ // use for login data.
        email: "",
        password: "",
    });

    // function for set login data.
    const handleSubmit = (e) => {
        // set login data to state.
        setLoginData({ ...loginData, [e.target.name]: e.target.value});
    };

    // function for handle login form submit.
    const handleOnSubmit = async (e) => {
        e.preventDefault();
        setLoading(true); // set loading state to true.

        try {
            
            // make api call to login user.
            const response = await AxiosInstance.post('login/',loginData);

            // if api call success.
            if(response.status === 200){
                const responseData = response.data;

                const user = {
                    username : responseData.username,
                    email : responseData.email,

                };

                // set user data to local storage.
                localStorage.setItem("token", JSON.stringify(responseData.access_token));

                // set refresh token to local storage.
                localStorage.setItem("refresh_token", JSON.stringify(responseData.refresh_token));

                // set user data to local storage.
                localStorage.setItem("user", JSON.stringify(user));

                // navigate to dashboard after login.
                navigate("/dashboard");

                toast.success("Login Successful"); // show success message.

            } else{
                toast.error("Something went wrong, Login Failed..!"); // show error message.
            }


        } catch (error) {
            
            // Show error with message.
            toast.error("Something went wrong, Login Failed..!",error.response || error.message);
            console.error("Login Failed:", error.response || error.message);
        } finally{
            setLoading(false); // set loading state to false
        }
    }

return{
    loginData,
    handleSubmit,
    handleOnSubmit,
    loading,
};

};

export default useLogin;