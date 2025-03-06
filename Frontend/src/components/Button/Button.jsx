import { useState } from "react";
import { Button } from "antd";
import "../style.css";
import PropTypes from "prop-types";

const CustomButton = ({
  // type = "primary",
  size = "middle",
  shape = "default",
  loading: propLoading, // Accepting loading state from props
  disabled = false,
  onClick,
  className = "",
  icon = null,
  children,
  ...rest
}) => {
  const [loading, setLoading] = useState(false);

  const handleClick = () => {
    if (onClick) onClick();
    setLoading(true);
    setTimeout(() => setLoading(false), 2000); // Reset loading after 2s
  };

  return (
    <Button
      // type={type}
      size={size}
      shape={shape}
      loading={propLoading ?? loading} // If propLoading is passed, use it; otherwise, use state
      disabled={disabled || loading} // Disable button while loading
      onClick={handleClick}
      className={`custom-button ${className}`}
      icon={icon}
      {...rest}
    >
      {loading ? "Loading..." : children}
    </Button>
  );
};

CustomButton.propTypes = {
  // type: PropTypes.string,
  size: PropTypes.string,
  shape: PropTypes.string,
  loading: PropTypes.bool,
  disabled: PropTypes.bool,
  onClick: PropTypes.func,
  className: PropTypes.string,
  icon: PropTypes.node,
  children: PropTypes.node,
};

export default CustomButton;
