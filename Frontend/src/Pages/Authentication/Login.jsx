import { useState } from "react";
import { Form } from "antd";
import { MailOutlined, LockOutlined } from "@ant-design/icons";
import { CustomButton, InputField } from "../../components/index";
import { Link } from "react-router-dom";
import "./style.css";
const Login = () => {
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
        <LockOutlined style={{ marginRight: "8px" }} />
        Login Here
      </h1>
      <Form
        form={form}
        layout="vertical"
        onFinish={onFinish}
        className="reg-log-form"
      >
        <InputField
          name="email"
          label="Email"
          placeholder="Email"
          type="email"
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
          label="Password"
          placeholder="Password"
          type="password"
          prefixIcon={<LockOutlined />}
          rules={[
            {
              required: true,
              message: "Please enter your password",
            },
          ]}
        />
        <div className="reg-log-footer">
          <p>
            Don&apos;t have an account?{" "}
            <Link className="linked" to="/register">
              Register here.
            </Link>
          </p>
        </div>
        <div className="center-button">
          <CustomButton
            className="custom-button"
            size="large"
            htmlType="submit"
            loading={loading}
          >
            {loading ? "Logging in..." : "Login"}
          </CustomButton>
        </div>
      </Form>
    </div>
  );
};

export default Login;
