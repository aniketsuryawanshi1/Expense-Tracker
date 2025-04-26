import { useState } from "react";
import { Button } from "antd";
import "../style.css";
import PropTypes from "prop-types";

const CustomButton = ({
  size = "middle",
  shape = "default",
  loading: propLoading, // Accepting loading state from props
  disabled = false,
  onClick,
  className = "",
  icon = null,
  children,
  ...rest // Other props to pass to the button dynamically.
}) => {
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    if (onClick) {
      setLoading(true);
      await onClick();
      setLoading(false);
    }
  };

  return (
    <Button
      size={size}
      shape={shape}
      loading={propLoading ?? loading} // If propLoading is passed, use it; otherwise, use state
      disabled={disabled || loading} // Disable button while loading
      onClick={handleClick}
      className={`custom-button ${className}`}
      icon={icon}
      {...rest}
    >
      {loading ? "Loading..." : children} {/* Show loading text if loading.*/}
    </Button>
  );
};

CustomButton.propTypes = {
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
