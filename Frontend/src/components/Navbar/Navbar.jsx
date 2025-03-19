import { Layout, Menu, Button, Drawer } from "antd";
import { useState, useEffect } from "react";
import { MenuOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";

import logo from "../../assets/Images/expense-tracker-high-logo.svg";

const { Header } = Layout;

const Navbar = () => {
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const navigate = useNavigate();

  const items = [
    { key: "1", label: "Home", onClick: () => navigate("/") },
    { key: "2", label: "About", onClick: () => navigate("/about") },
    { key: "3", label: "Services", onClick: () => navigate("/services") },
    { key: "4", label: "Contact", onClick: () => navigate("/contact") },
  ];

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const showDrawer = () => setDrawerOpen(true);
  const closeDrawer = () => setDrawerOpen(false);

  const handleLoginClick = () => navigate("/login");
  const handleRegisterClick = () => navigate("/register");

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
      <div
        style={{ flex: 1, marginTop: 20, textAlign: isMobile ? "center" : "left", cursor: "pointer" }}
        onClick={() => navigate("/")}
      >
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
              <Button type="primary" block onClick={handleLoginClick}>Login</Button>
              <Button style={{ marginTop: "10px" }} block onClick={handleRegisterClick}>Register</Button>
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
            <Button type="primary" onClick={handleLoginClick}>Login</Button>
            <Button onClick={handleRegisterClick}>Register</Button>
          </div>
        </>
      )}
    </Header>
  );
};

export default Navbar;
