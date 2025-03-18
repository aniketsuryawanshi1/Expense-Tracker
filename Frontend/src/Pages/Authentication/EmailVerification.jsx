import { useState, useEffect } from "react";
import { Card, Input, Form, Typography, message, Button } from "antd";
import { MailOutlined, LoadingOutlined, CheckOutlined } from "@ant-design/icons";
import { useNavigate, useLocation } from "react-router-dom"; // Import useLocation
import { CustomButton } from "../../components/index";
import axios from "axios";

import "../../components/style.css";
const { Title, Text } = Typography;

const OTPVerification = () => {
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [loading, setLoading] = useState(false);
  const [timeLeft, setTimeLeft] = useState(60); // Update timer to 60 seconds
  const [canResend, setCanResend] = useState(false);
  const navigate = useNavigate();
  const location = useLocation(); // Get the current location

  const isPasswordReset = location.pathname.includes("password-reset"); // Check if it's for password reset

  const handleChange = (value, index) => {
    if (/^\d$/.test(value) || value === "") {
      const newOtp = [...otp];
      newOtp[index] = value;
      setOtp(newOtp);

      if (value && index < 5) {
        document.getElementById(`otp-${index + 1}`).focus();
      }
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Backspace") {
      const newOtp = [...otp];

      if (otp[index] === "") {
        if (index > 0) {
          document.getElementById(`otp-${index - 1}`).focus();
        }
      } else {
        newOtp[index] = "";
        setOtp(newOtp);
      }
    }

    if (e.key === "ArrowLeft" && index > 0) {
      document.getElementById(`otp-${index - 1}`).focus();
    }

    if (e.key === "ArrowRight" && index < 3) {
      document.getElementById(`otp-${index + 1}`).focus();
    }
  };

  useEffect(() => {
    if (otp.every((digit) => digit !== "")) {
      console.log("Final OTP:", otp.join(""));
    }
  }, [otp]);

  useEffect(() => {
    if (timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
      return () => clearTimeout(timer);
    } else {
      setCanResend(true);
    }
  }, [timeLeft]);

  const handleSubmit = async () => {
    const finalOtp = otp.join("");
    try {
      setLoading(true);
      const endpoint = isPasswordReset
        ? "http://localhost:8000/api/password-reset/"
        : "http://localhost:8000/api/verify-otp/";
      const response = await axios.post(endpoint, { otp: finalOtp });
      if (response.status === 200) {
        message.success(isPasswordReset ? "OTP verified, Please reset your password" : "Email verified, Please login");
        navigate(isPasswordReset ? "/reset-password" : "/login");
      }
    } catch (err) {
      message.error(err.response?.data?.message || "Verification Failed");
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = () => {
    navigate("/resend-otp"); // Ensure this path matches the route for RequestAction component
  };

  return (
    <div className="otp-container">
      <Card hoverable className="otp-card">
        <MailOutlined className="otp-icon" />
        <Title level={3}>{isPasswordReset ? "Password Reset" : "Email Verification"}</Title>
        <Text style={{ marginBottom: "20px", display: "block" }}>
          {isPasswordReset ? "Please enter the OTP sent to your email to reset your password" : "Please enter the OTP sent to your email"}
        </Text>

        <Form onFinish={handleSubmit}>
          <div className="otp-input-wrapper">
            {otp.map((digit, index) => (
              <Input
                key={index}
                id={`otp-${index}`}
                maxLength={1}
                value={digit}
                onChange={(e) => handleChange(e.target.value, index)}
                onKeyDown={(e) => handleKeyDown(e, index)}
                style={{
                  width: 50,
                  height: 40,
                  textAlign: "center",
                  margin: "0 5px",
                }}
                autoFocus={index === 0}
              />
            ))}
          </div>
          <CustomButton
            type="primary"
            htmlType="submit"
            loading={loading}
            className="custom-button"
            style={{ marginTop: "20px", width: "100%", maxWidth: "300px"}}
            icon={loading ? <LoadingOutlined /> : <CheckOutlined />}
          >
            {loading ? "Verifying..." : "Verify"}
          </CustomButton>
        </Form>
        <Text style={{ marginTop: "20px", display: "block" }}>
          {timeLeft > 0 ? `OTP expires in ${timeLeft} seconds` : "OTP expired"}
        </Text>
        {canResend && (
          <Button
            type="link"
            onClick={handleResendOtp}
            disabled={loading}
            style={{ marginTop: "10px" }}
          >
            Resend OTP
          </Button>
        )}
      </Card>
    </div>
  );
};

export default OTPVerification;
