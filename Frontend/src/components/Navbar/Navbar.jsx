import { Layout, Menu, Button, Drawer } from "antd";
import { useState, useEffect } from "react";
import { MenuOutlined } from "@ant-design/icons";

import logo from "../../assets/Images/expense-tracker-high-logo.svg";

const { Header } = Layout;

const items = [
  { key: "1", label: "Home" },
  { key: "2", label: "About" },
  { key: "3", label: "Services" },
  { key: "4", label: "Contact" },
];

const Navbar = () => {
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const showDrawer = () => setDrawerOpen(true);
  const closeDrawer = () => setDrawerOpen(false);

  return (
    <Header
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "10px 20px",
        background: "white",
        boxShadow: "0 2px 10px rgba(0, 0, 0, 0.1)",
      }}
    >
      {/* Logo */}
      <div style={{ flex: 1, marginTop: 20, textAlign : isMobile ? "center" : "left" }}>
        <img
          src={logo}
          alt="Expense Tracker Logo"
          style={{ height: isMobile ? "70px" : "80px" }}
        />
      </div>

      {isMobile ? (
        <>
          <MenuOutlined
            style={{ fontSize: "24px", cursor: "pointer" }}
            onClick={showDrawer}
          />
          <Drawer
            title="Menu"
            placement="right"
            onClose={closeDrawer}
            open={drawerOpen}
            width={250}
          >
            <Menu mode="vertical" items={items} />
            <div style={{ marginTop: "20px", textAlign: "center" }}>
              <Button type="primary" block>Login</Button>
              <Button style={{ marginTop: "10px" }} block>Register</Button>
            </div>
          </Drawer>
        </>
      ) : (
        <>
          <Menu
            mode="horizontal"
            items={items}
            style={{
              flex: 1,
              justifyContent: "center",
              background: "transparent",
            }}
          />
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <Button type="primary">Login</Button>
            <Button>Register</Button>
          </div>
        </>
      )}
    </Header>
  );
};

export default Navbar;
