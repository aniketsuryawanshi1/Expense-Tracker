import { Form,Button } from "antd";
import {
  MailOutlined,
  UserOutlined,
  LockOutlined,
  UserAddOutlined,
} from "@ant-design/icons";
import {   InputField } from "../../components/index";
import { Link } from "react-router-dom";
import useRegister from "../../hooks/Authentication/useRegister";
import "./style.css";

const Register = () => {
  const [form] = Form.useForm();
  const { handleOnSubmit, loading } = useRegister();

  console.log("Component Rendered");

  const onFinish = (values) => {
    console.log("Form Submitted Data:", values); // ✅ Debugging
    handleOnSubmit(values, () => form.resetFields()); // API call with form reset
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
          label="Username"
          placeholder="Enter Username"
          prefixIcon={<UserOutlined />}
          rules={[{ required: true, message: "Please enter your username" }]}
        />

        <InputField
          name="email"
          label="Email"
          placeholder="Enter Email"
          prefixIcon={<MailOutlined />}
          rules={[
            { required: true, message: "Please enter your email" },
            { type: "email", message: "Invalid email format" },
          ]}
        />

        <InputField
          name="password"
          label="Password"
          placeholder="Enter Password"
          prefixIcon={<LockOutlined />}
          type="password"
          rules={[{ required: true, message: "Please enter your password" }]}
        />

        <InputField
          name="password2"
          label="Confirm Password"
          placeholder="Confirm Password"
          prefixIcon={<LockOutlined />}
          type="password"
          dependencies={["password"]}
          rules={[
            { required: true, message: "Please confirm your password" },
            ({ getFieldValue }) => ({
              validator(_, value) {
                if (!value || getFieldValue("password") === value) {
                  return Promise.resolve();
                }
                return Promise.reject("Passwords do not match!");
              },
            }),
          ]}
        />

        <div className="reg-log-footer">
          <p>
            Already have an account?{" "}
            <Link className="linked" to="/login">
              Login here
            </Link>
          </p>
        </div>

        <div className="center-button">

          <Button
            type="primary"
            htmlType="submit"
            style={{ marginTop: "20px",
              width: "100%",
              maxWidth: "300px",
              padding: "20px",
            }}
            loading={loading}
            className="custom-button"
          >
            {loading ? "Registering..." : "Register"}
          </Button>

        </div>
      </Form>
    </div>
  );
};

export default Register;
