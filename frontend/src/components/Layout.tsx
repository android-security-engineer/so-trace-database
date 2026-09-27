import { Layout, Menu, Avatar, Dropdown, Typography, Space } from 'antd'
import {
  DashboardOutlined,
  FileOutlined,
  CodeOutlined,
  UserOutlined,
  LogoutOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'

const { Header, Sider, Content } = Layout
const { Text } = Typography

export default function MainLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { username, logout } = useAuth()

  const menuItems = [
    { key: '/dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
    { key: '/so-files', icon: <FileOutlined />, label: 'SO 文件' },
    { key: '/traces', icon: <CodeOutlined />, label: 'Trace 会话' },
    { key: '/traces/0/threads', icon: <ThunderboltOutlined />, label: '线程分析' },
  ]

  const userMenuItems = [
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录' },
  ]

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={200} theme="light">
        <div style={{ height: 64, display: 'flex', alignItems: 'center', justifyContent: 'center', borderBottom: '1px solid #f0f0f0' }}>
          <Text strong style={{ fontSize: 16 }}>SO Trace DB</Text>
        </div>
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ borderRight: 0 }}
        />
      </Sider>
      <Layout>
        <Header style={{ background: '#fff', padding: '0 24px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', borderBottom: '1px solid #f0f0f0' }}>
          <Dropdown menu={{ items: userMenuItems, onClick: ({ key }) => { if (key === 'logout') { logout(); navigate('/login') } } }}>
            <Space style={{ cursor: 'pointer' }}>
              <Avatar icon={<UserOutlined />} />
              <Text>{username}</Text>
            </Space>
          </Dropdown>
        </Header>
        <Content style={{ margin: 24, padding: 24, background: '#fff', borderRadius: 8, minHeight: 360 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
