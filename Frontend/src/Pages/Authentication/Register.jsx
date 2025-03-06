import { useState } from "react";
import { Form } from "antd"; // Correct import
import {
  MailOutlined,
  UserOutlined,
  LockOutlined,
  UserAddOutlined,
} from "@ant-design/icons";
import { CustomButton, InputField } from "../../components/index"
import { Link } from "react-router-dom";
import "./style.css";

const Register = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);

  // Handle form submission
  const onFinish = (values) => {
    console.log("Form Values:", values);
    setLoading(true);

    // Simulate an API call
    setTimeout(() => setLoading(false), 2000);
  };

  return (
    <div className="reg-log-container">
      <h1 className="reg-log-title">
        <UserAddOutlined style={{ marginRight: "8px" }} />
        Register Here
      </h1>

      <Form
        form={form}
        layout="vertical"
        onFinish={onFinish}
        className="register-form"
      >
        <InputField
          name="username"
          label="Enter Username"
          placeholder="Username"
          prefixIcon={<UserOutlined />}
          rules={[
            {
              required: true,
              message: "Please enter your username",
            },
          ]}
        />
        <InputField
          name="email"
          label="Enter Email"
          placeholder="Enter your email"
          prefixIcon={<MailOutlined />}
          rules={[
            {
              required: true,
              message: "Please enter your email",
            },
          ]}
        />
        <InputField
          name="password"
          label="Enter Password"
          placeholder="Password"
          prefixIcon={<LockOutlined />}
          type="password"
          rules={[
            {
              required: true,
              message: "Please enter your password",
            },
          ]}
        />
        <InputField
          name="password2"
          label="Confirm Password"
          placeholder="Confirm Password"
          type="password"
          prefixIcon={<LockOutlined />}
          rules={[
            {
              required: true,
              message: "Please confirm your password",
            },
          ]}
        />
        <div className="reg-log-footer">
          <p>
            Already have an account?{" "}
            <Link className="linked" to="/login">
              Login here.
            </Link>
          </p>
        </div>

        <div className="center-button">
          <CustomButton
            className="custom-button"
            size="large"
            loading={loading}
            htmlType="submit"
          >
            {loading ? "Registering..." : "Register"}
          </CustomButton>
        </div>
      </Form>
    </div>
  );
};

export default Register;
