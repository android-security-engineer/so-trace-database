import { Alert, Button, Col, ConfigProvider, Layout, Menu, Row, Typography, theme } from 'antd'
import Story from './Story'

const { Header, Content, Footer } = Layout
const { Paragraph, Title } = Typography

const install = `curl -fsSL -o sotrace https://github.com/android-security-engineer/so-trace-database/releases/download/v0.1.0/sotrace-linux-x86_64
chmod +x sotrace
./sotrace --help`

export default function App() {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#0e6b5c',
          colorText: '#1c2430',
          colorBgBase: '#eef3f0',
          fontFamily: '"Noto Sans SC", "Source Han Sans SC", sans-serif',
          borderRadius: 2,
        },
      }}
    >
      <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
        <Header className="site-nav" aria-label="导航">
          <a className="site-mark" href="#hero">
            SO Trace Database
          </a>
          <Menu
            mode="horizontal"
            selectable={false}
            style={{ flex: 1, minWidth: 0, background: 'transparent', border: 'none' }}
            items={[
              { key: 'product', label: <a href="#hero">产品</a> },
              { key: 'problem', label: <a href="#problem">问题</a> },
              { key: 'fix', label: <a href="#fix">怎么解决</a> },
              { key: 'usage', label: <a href="#usage">用法</a> },
              { key: 'throughput', label: <a href="#throughput">吞吐</a> },
              { key: 'boundary', label: <a href="#boundary">边界</a> },
            ]}
          />
          <Button type="primary" href="#usage">
            安装
          </Button>
        </Header>

        <Content>
          <section className="site-hero" id="hero">
            <div>
              <Title level={1}>纯文本的 SO trace，收成可以查询的数据库。</Title>
              <Paragraph style={{ fontSize: 18, maxWidth: 560 }}>
                对 SO，包括 VMP 加密的 SO 做 trace 时，输出通常是一大份纯文本日志。要在里面检索和分析不太方便。SO Trace Database 把这份纯文本变成结构化、可查询的数据库。
              </Paragraph>
              <Paragraph style={{ maxWidth: 560 }}>
                它不是 trace 采集工具，不替代 Frida、Pin 或 DynamoRIO。它也不是符号执行框架。
              </Paragraph>
              <Button type="primary" size="large" href="#usage" style={{ marginRight: 12 }}>
                查看安装命令
              </Button>
              <Button size="large" href="https://github.com/android-security-engineer/so-trace-database">
                仓库
              </Button>
            </div>
            <div className="trace-ledger" aria-label="纯文本日志和结构化记录">
              <table>
                <thead>
                  <tr>
                    <th>纯文本日志</th>
                    <th>结构化记录</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>pc=0x1000 bl</td>
                    <td>指令</td>
                  </tr>
                  <tr>
                    <td>mem write 0x2000</td>
                    <td>内存</td>
                  </tr>
                  <tr>
                    <td>x0 = 返回值</td>
                    <td>寄存器</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <Story />

          <section className="band band-rule" id="problem">
            <Title level={2}>问题</Title>
            <Paragraph style={{ fontSize: 18, maxWidth: 720 }}>
              对 SO，包括 VMP 加密的 SO 做 trace，出来的往往是一大份纯文本日志。要在这种文本里检索和分析不太方便：想按指令、内存或寄存器把一次执行对上，只能自己翻行。
            </Paragraph>
          </section>

          <section className="band band-rule" id="fix">
            <Title level={2}>怎么解决</Title>
            <Paragraph style={{ fontSize: 18, maxWidth: 720 }}>
              把这份纯文本 trace 日志变成结构化、可查询的数据库，分析就不用在文本里翻。用 trace-save 存下指令、内存和寄存器记录，再用 query 把已经存好的一条记录读出来。
            </Paragraph>
          </section>

          <section className="band band-rule" id="stores">
            <Title level={2}>轨迹里能查的东西</Title>
            <Row gutter={[32, 24]}>
              <Col xs={24} md={8}>
                <Title level={4}>指令</Title>
                <Paragraph>按步号和 SO 内地址找回执行过的指令，而不是只看反汇编里的静态序列。</Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Title level={4}>内存与寄存器</Title>
                <Paragraph>写入和寄存器变化按步重建。二进制里看不到的那次结果，存在轨迹里。</Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Title level={4}>调用与线程</Title>
                <Paragraph>调用关系和线程事件跟指令走同一条时间线，按线程把一次执行拆开。</Paragraph>
              </Col>
            </Row>
          </section>

          <section className="band band-rule" id="usage">
            <Row gutter={[40, 24]} align="middle">
              <Col xs={24} md={10}>
                <Title level={2}>怎么用</Title>
                <Paragraph>
                  Linux x86_64 复制右边这段。它下载已发布的 sotrace-linux-x86_64，并把它当成可执行的 sotrace。
                </Paragraph>
                <Paragraph style={{ marginBottom: 0 }}>
                  存一条轨迹用 trace-save。再把它查出来用 query。
                </Paragraph>
              </Col>
              <Col xs={24} md={14}>
                <pre className="install-fence">{install}</pre>
              </Col>
            </Row>
          </section>

          <section className="band band-rule" id="throughput">
            <Title level={2}>这台机器上的写入吞吐</Title>
            <Paragraph>
              下面两个数是本机 release 二进制的样本中位数，不是可移植的 SLA。内存导入和耐久落盘是两条分开的速率。
            </Paragraph>
            <div className="rate-pair">
              <div>
                <span>内存里的 TraceEngine::feed_events</span>
                <strong>6445831</strong>
                <span>条/秒。5 次试验的中位数，导入时不 fsync。</span>
              </div>
              <div>
                <span>含持久化的耐久写入</span>
                <strong>3617370</strong>
                <span>条/秒。3 次试验 ingest_events_sec 的中位数，每次 200000 条并落盘。</span>
              </div>
            </div>
          </section>

          <section className="band band-rule" id="boundary">
            <Alert
              type="warning"
              showIcon
              message="这些目标还没有验收"
              description="相对原始文本 10 倍压缩、单次不少于 10 亿条记录、单个数据库不少于 100GB，以及 SPEC §6.2 的查询延迟，都还不是已经验收的结果，也不能当成 SLA。这一版是一个 sotrace-server 进程。"
            />
          </section>
        </Content>

        <Footer style={{ background: '#1c2430', color: '#e7eee9' }}>
          <div className="band" style={{ paddingBottom: 8 }}>
            <div className="site-mark">SO Trace Database</div>
            <Paragraph style={{ color: '#e7eee9', margin: '8px 0 0' }}>
              Android SO 执行轨迹的存储与查询。
            </Paragraph>
          </div>
        </Footer>
      </Layout>
    </ConfigProvider>
  )
}
