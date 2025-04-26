import { useState } from "react";
import { Dropdown } from "antd";
import {
  DownOutlined,
  SettingOutlined,
  InfoCircleOutlined,
  LogoutOutlined,
} from "@ant-design/icons";
import "../style.css";

const ProfileDropdown = () => {
  const [hovered, setHovered] = useState(false);

  // Get userdata from local storage.
  const data = JSON.parse(localStorage.getItem("user"));

  const handleMenuClick = ({ key }) => {
    if (key === "settings") {
      console.log("Settings Clicked");
    } else if (key === "details") {
      console.log("Details Clicked");
    } else if (key === "logout") {
      console.log("Logged out!");
    }
  };

  const menuProps = {
    items: [
      {
        key: "settings",
        icon: <SettingOutlined />,
        label: "Settings",
      },
      {
        key: "details",
        icon: <InfoCircleOutlined />,
        label: "Details",
      },
      {
        key: "logout",
        icon: <LogoutOutlined />,
        label: "Logout",
        danger: true,
      },
    ],
    onClick: handleMenuClick,
    className: "profile-dropdown-menu",
  };

  return (
    <div
      className="profile-dropdown-container"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <Dropdown menu={menuProps} placement="bottom" arrow>
        <div className={`profile-dropdown ${hovered ? "hovered" : ""}`}>
          <img src={data.image} alt="Profile" className="profile-image" />
          <span className={`profile-username ${hovered ? "hovered" : ""}`}>
            {data.username} <DownOutlined />
          </span>
        </div>
      </Dropdown>
    </div>
  );
};

export default ProfileDropdown;
