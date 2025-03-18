import { useState } from "react";
import { Form, message } from "antd";
import { LockOutlined } from "@ant-design/icons";
import { InputField, CustomButton } from "../../components/index";
import "./test.css";
const SetNewPassword = () => {
  const [loading, setLoading] = useState(false);

  const onFinish = async (values) => {
    setLoading(true);
    try {
      // Handle password reset logic here
      console.log("New Password:", values.password);
      console.log("Confirm Password:", values.password2);
      message.success("Password reset successfully!");
    } catch {
      message.error("Failed to reset password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="set-new-password-container">
      <h2>Set New Password</h2>
      <Form
        name="set_new_password"
        onFinish={onFinish}
        layout="vertical"
        className="set-new-password-form"
      >
        <InputField
          name="password"
          label="New Password"
          placeholder="Enter new password"
          type="password"
          prefixIcon={<LockOutlined />}
          rules={[
            { required: true, message: "Please input your new password!" },
          ]}
        />
        <InputField
          name="password2"
          label="Confirm Password"
          placeholder="Confirm new password"
          type="password"
          prefixIcon={<LockOutlined />}
          rules={[
            { required: true, message: "Please confirm your new password!" },
            ({ getFieldValue }) => ({
              validator(_, value) {
                if (!value || getFieldValue("password") === value) {
                  return Promise.resolve();
                }
                return Promise.reject(
                  new Error("The two passwords do not match!")
                );
              },
            }),
          ]}
        />
        <Form.Item>
          <CustomButton
            type="primary"
            htmlType="submit"
            loading={loading}
            disabled={loading}
          >
            Reset Password
          </CustomButton>
        </Form.Item>
      </Form>
    </div>
  );
};

export default SetNewPassword;