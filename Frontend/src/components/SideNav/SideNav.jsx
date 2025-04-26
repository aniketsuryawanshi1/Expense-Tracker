import { useState, useEffect } from "react";
import { Layout, Menu, Button, Drawer } from "antd";
import {
  HomeOutlined,
  FileTextOutlined,
  PlusCircleOutlined,
  LogoutOutlined,
  AppstoreAddOutlined,
  MenuOutlined,
  MenuUnfoldOutlined,
  MenuFoldOutlined,
} from "@ant-design/icons";
import useLogout from "../../hooks/Authentication/useLogout";
import { useNavigate } from "react-router-dom";

const { Sider } = Layout;

const SideNav = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const navigate = useNavigate();

  const handelLogout = useLogout();

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const menuItems = [
    {
      key: "1",
      icon: <HomeOutlined />,
      label: "Dashboard",
      onClick: () => navigate("/dashboard"),
    },
    {
      key: "2",
      icon: <FileTextOutlined />,
      label: "Generate Report",
      onClick: () => navigate("/generatereport"),
    },
    {
      key: "3",
      icon: <PlusCircleOutlined />,
      label: "Add New",
      onClick: () => navigate("/addnew"),
    },
    {
      key: "4",
      icon: <AppstoreAddOutlined />,
      label: "Add Category",
      onClick: () => navigate("/addcategory"),
    },
    {
      key: "5",
      icon: <LogoutOutlined />,
      label: "Logout",
      onClick: () => handelLogout(),
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
