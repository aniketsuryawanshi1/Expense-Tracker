import { useState, useEffect } from "react";
import { Card, Input, Form, Typography, message } from "antd";
import { MailOutlined, LoadingOutlined, CheckOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { CustomButton } from "../../components/index";
import axios from "axios";

import "../../components/style.css";
const { Title, Text } = Typography;

const OTPVerification = () => {
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

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

  const handleSubmit = async () => {
    const finalOtp = otp.join("");
    try {
      setLoading(true);
      const response = await axios.post(
        "http://localhost:8000/api/verify-otp/",
        { otp: finalOtp }
      );
      if (response.status === 200) {
        message.success("Email verified, Please login");
        navigate("/login");
      }
    } catch (err) {
      message.error(err.response?.data?.message || "Verification Failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="otp-container">
      <Card hoverable className="otp-card">
        <MailOutlined className="otp-icon" />
        <Title level={3}>Email Verification</Title>
        <Text style={{ marginBottom: "20px", display: "block" }}>
          Please enter the OTP sent to your email
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
            // add some custom style
            style={{ marginTop: "20px", width: "100%", maxWidth: "300px"}}
            icon={loading ? <LoadingOutlined /> : <CheckOutlined />}
          >
            {loading ? "Verifying..." : "Verify"}
          </CustomButton>
        </Form>
      </Card>
    </div>
  );
};

export default OTPVerification;
