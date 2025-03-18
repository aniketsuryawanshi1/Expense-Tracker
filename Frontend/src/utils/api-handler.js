import axios from "axios";
import { jwtDecode } from "jwt-decode";
import dayjs from "dayjs";

const BASE_URL = "http://localhost:8000/api/";

const getTokenFromStorage = (key) => {
  const storedToken = localStorage.getItem(key);
  if (storedToken && storedToken !== "undefined") {
    return storedToken;
  }
  return "";
};

let accessToken = getTokenFromStorage("token");
let refreshToken = getTokenFromStorage("refresh_token");

const AxiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
    Authorization: accessToken ? `Bearer ${accessToken}` : "",
  },
});

// Request Interceptor
AxiosInstance.interceptors.request.use(
  async (req) => {
    if (accessToken) {
      try {
        const user = jwtDecode(accessToken);
        const isExpired = dayjs.unix(user.exp).diff(dayjs()) < 1;

        if (!isExpired) {
          req.headers.Authorization = `Bearer ${accessToken}`;
          return req;
        }

        console.log("Access token expired, attempting to refresh...");

        if (!refreshToken) {
          console.error("No refresh token available, redirecting to login.");
          localStorage.removeItem("token");
          localStorage.removeItem("refresh_token");
          window.location.href = "/login";
          return Promise.reject("No refresh token");
        }

        const response = await axios.post(`${BASE_URL}token/refresh/`, {
          refresh: refreshToken,
        });

        if (response.data.access) {
          const newAccessToken = response.data.access;
          localStorage.setItem("token", newAccessToken);
          req.headers.Authorization = `Bearer ${newAccessToken}`;
          accessToken = newAccessToken;
          console.log("Token refreshed successfully");
          return req;
        }
      } catch (error) {
        console.error("Token refresh failed:", error.response?.data || error.message);
        localStorage.removeItem("token");
        localStorage.removeItem("refresh_token");
        window.location.href = "/login";
        return Promise.reject(error);
      }
    }
    return req;
  },
  (error) => {
    console.error("Request error:", error);
    return Promise.reject(error);
  }
);

// Response Interceptor
AxiosInstance.interceptors.response.use(
  (response) => {
    console.log("Response received:", response);
    return response;
  },
  (error) => {
    if (error.response) {
      console.error("Response error:", error.response.data);
    } else {
      console.error("Network or other error:", error.message);
    }
    return Promise.reject(error);
  }
);

export default AxiosInstance;
