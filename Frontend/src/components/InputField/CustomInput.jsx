import { useState } from "react";
import PropTypes from "prop-types";
import { Form, Input, Select, Upload } from "antd";
import { UploadOutlined } from "@ant-design/icons";
import CustomButton from "../Button/Button";
import "../style.css";

const { Option } = Select;

const InputField = (props) => {
  const {
    name,
    label,
    placeholder,
    rules = [],
    type = "text",
    prefixIcon = null,
    className = "",
    buttonText = "Upload",
    buttonSize = "middle",
    buttonShape = "default",
    dropdownOptions = [],
    options = [],
    ...restProps
  } = props;

  // State for input value
  const [inputValue, setInputValue] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

  // Handle input changes
  const handleChange = (e) => {
    setInputValue(e.target.value);
  };

  // Handle file upload change
  const handleFileChange = ({ file }) => {
    setSelectedFile(file.name); // Save uploaded file name in state
  };

  return (
    <Form.Item
      name={name}
      label={label}
      rules={rules}
      className={`custom-input ${className}`}
    >
      {type === "file" ? (
        <Upload
          {...restProps}
          listType="picture"
          showUploadList={{ showPreviewIcon: true, showRemoveIcon: true }}
          beforeUpload={() => false} // Prevent auto upload
          onChange={handleFileChange}
        >
          <CustomButton
            type="primary"
            size={buttonSize}
            shape={buttonShape}
            icon={<UploadOutlined />}
          >
            {selectedFile ? selectedFile : buttonText}
          </CustomButton>
        </Upload>
      ) : type === "select" || type === "dropdown" ? (
        <Select
          placeholder={placeholder}
          {...restProps}
          onChange={(value) => setInputValue(value)}
        >
          {(dropdownOptions.length > 0 ? dropdownOptions : options).map(
            (option) => (
              <Option key={option.value} value={option.value}>
                {option.label}
              </Option>
            )
          )}
        </Select>
      ) : type === "textarea" ? (
        <Input.TextArea
          placeholder={placeholder}
          className={`custom-textarea ${className}`}
          size="large"
          value={inputValue}
          onChange={handleChange}
          {...restProps}
        />
      ) : (
        <Input
          type={type}
          placeholder={placeholder}
          prefix={prefixIcon}
          className={`custom-input-field ${className}`}
          size="large"
          value={inputValue}
          onChange={handleChange}
          {...restProps}
        />
      )}
    </Form.Item>
  );
};

InputField.propTypes = {
  name: PropTypes.string.isRequired,
  label: PropTypes.string,
  placeholder: PropTypes.string,
  rules: PropTypes.array,
  type: PropTypes.string,
  prefixIcon: PropTypes.element,
  className: PropTypes.string,
  buttonText: PropTypes.string,
  buttonSize: PropTypes.string,
  buttonShape: PropTypes.string,
  dropdownOptions: PropTypes.array,
  options: PropTypes.array,
};

export default InputField;
