import { useState } from "react";
import { Card, Input, Form, Typography, message } from "antd";
import { MailOutlined } from "@ant-design/icons";
import { useNavigate, useLocation } from "react-router-dom"; // Import useLocation
import { CustomButton } from "../../components/index";
import axios from "axios";

import "../../components/style.css";
const { Title, Text } = Typography;

const RequestAction = () => {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation(); // Get the current location

  const isPasswordReset = location.pathname.includes("password-reset"); // Check if it's for password reset

  const handleSubmit = async () => {
    try {
      setLoading(true);
      const endpoint = isPasswordReset
        ? "http://localhost:8000/api/password-reset/" // Ensure this endpoint is correct
        : "http://localhost:8000/api/otp/resend/";
      const response = await axios.post(endpoint, { email });
      if (response.status === 200) {
        message.success(isPasswordReset ? "Password reset link sent successfully" : "OTP resent successfully");
        navigate(isPasswordReset ? "/reset-password" : "/verify-email");
      }
    } catch (err) {
      message.error(err.response?.data?.message || "Failed to send request");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="resend-otp-container">
      <Card hoverable className="resend-otp-card">
        <MailOutlined className="resend-otp-icon" />
        <Title level={3}>{isPasswordReset ? "Password Reset" : "Resend OTP"}</Title>
        <Text style={{ marginBottom: "20px", display: "block" }}>
          {isPasswordReset ? "Please enter your email to receive a password reset link" : "Please enter your email to resend the OTP"}
        </Text>

        <Form onFinish={handleSubmit}>
          <Form.Item
            name="email"
            rules={[{ required: true, message: "Please input your email!" }]}
          >
            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email"
              style={{ width: "100%", maxWidth: "300px" }}
            />
          </Form.Item>
          <CustomButton
            type="primary"
            htmlType="submit"
            loading={loading}
            className="custom-button"
            style={{ width: "100%", maxWidth: "300px" }}
          >
            {loading ? "Sending..." : isPasswordReset ? "Send Reset Link" : "Send OTP"}
          </CustomButton>
        </Form>
      </Card>
    </div>
  );
};

export default RequestAction;
