import { Form } from "antd";
import { MailOutlined, LockOutlined, LoadingOutlined, LoginOutlined } from "@ant-design/icons";
import { InputField, CustomButton } from "../../components/index";
import { Link } from "react-router-dom";
import useLogin from "../../hooks/Authentication/useLogin"; // Import the hook
import "./style.css";

const Login = () => {
  const { handleOnSubmit, loading } = useLogin();
  const [form] = Form.useForm();

  const onFinish = (values) => {
    console.log("Form Submitted Data : ", values);
    handleOnSubmit(values, () => form.resetFields());
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
        onFinish={onFinish} // Use the custom hook function
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
            type="primary"
            htmlType="submit"
            loading={loading}
            className="custom-button"
            icon={loading ? <LoadingOutlined /> : <LoginOutlined />}
          >
            {loading ? "Logging in..." : "Login"}
          </CustomButton>
        </div>
      </Form>
    </div>
  );
};

export default Login;
