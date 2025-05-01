import { Avatar } from "antd";
import "../style.css";

const ProfileInfo = () => {
  const data = JSON.parse(localStorage.getItem("user"));
  const username = data?.username || "Guest";

  return (
    <div className="profile-info-container">
      <Avatar
        style={{
          backgroundColor: "#87d068",
          verticalAlign: "middle",
          fontSize: "24px",
        }}
        size="large"
      >
        {username.charAt(0).toUpperCase()}
      </Avatar>
      <span className="profile-username">{username}</span>
    </div>
  );
};

export default ProfileInfo;
