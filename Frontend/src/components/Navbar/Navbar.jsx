import { Layout, Menu, Input, Button, Switch } from "antd";
import { SearchOutlined, MoonOutlined, SunOutlined } from "@ant-design/icons";
import PropTypes from "prop-types";

const { Header } = Layout;

const items = [
  { key: "1", label: "Home" },
  { key: "2", label: "About" },
  { key: "3", label: "Services" },
  { key: "4", label: "Contact" },
];

const Navbar = ({ onThemeChange, theme = "light" }) => {
  return (
    <Header
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 20px",
        background: theme === "dark" ? "#001529" : "#ffffff",
      }}
    >
      {/* Logo */}
      <div
        className="logo"
        style={{
          color: theme === "dark" ? "white" : "black",
          fontSize: "20px",
          fontWeight: "bold",
        }}
      >
        MyLogo
      </div>

      {/* Navigation Menu */}
      <Menu
        theme={theme}
        mode="horizontal"
        defaultSelectedKeys={["1"]}
        items={items}
        style={{ flex: 1, justifyContent: "center", background: "transparent" }}
      />

      {/* Search Bar & Theme Toggle */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <Input placeholder="Search..." style={{ width: 200 }} />
        <Button type="primary" icon={<SearchOutlined />}>
          Search
        </Button>

        {/* Theme Toggle Switch */}
        <Switch
          checked={theme === "dark"}
          onChange={onThemeChange}
          checkedChildren={<MoonOutlined />}
          unCheckedChildren={<SunOutlined />}
        />
      </div>
    </Header>
  );
};

Navbar.propTypes = {
  onThemeChange: PropTypes.func.isRequired,
  theme: PropTypes.string,
};


export default Navbar;
