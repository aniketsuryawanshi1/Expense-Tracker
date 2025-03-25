import { useState, useEffect } from "react";
import { Layout, Menu, Button, Drawer } from "antd";
import {
  MenuUnfoldOutlined,
  MenuFoldOutlined,
  UserOutlined,
  VideoCameraOutlined,
  UploadOutlined,
  MenuOutlined,
} from "@ant-design/icons";
import { useNavigate } from "react-router-dom";

const { Sider } = Layout;

const SideNav = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const menuItems = [
    {
      key: "1",
      icon: <UserOutlined />,
      label: "Profile",
      onClick: () => navigate("/profile"),
    },
    {
      key: "2",
      icon: <VideoCameraOutlined />,
      label: "Dashboard",
      onClick: () => navigate("/dashboard"),
    },
    {
      key: "3",
      icon: <UploadOutlined />,
      label: "Uploads",
      onClick: () => navigate("/uploads"),
    },
  ];

  return (
    <>
      {isMobile ? (
        <>
          <Button
            type="text"
            icon={<MenuOutlined />}
            onClick={() => setDrawerOpen(true)}
          />
          <Drawer
            title="Menu"
            placement="left"
            closable
            onClose={() => setDrawerOpen(false)}
            open={drawerOpen}
            width={250}
          >
            <Menu theme="light" mode="vertical" items={menuItems} />
          </Drawer>
        </>
      ) : (
        <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed}>
          <div style={{ padding: 16, textAlign: "center", color: "white" }}>
            <Button
              type="text"
              icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => setCollapsed(!collapsed)}
              style={{ fontSize: "16px", color: "white" }}
            />
          </div>
          <Menu theme="dark" mode="inline" items={menuItems} />
        </Sider>
      )}
    </>
  );
};

export default SideNav;
