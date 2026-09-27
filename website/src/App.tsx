import { Alert, Card, ConfigProvider, Layout, Typography, theme } from 'antd'

const { Content } = Layout
const { Title, Paragraph } = Typography

export default function App() {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#8ab4ff',
          colorBgBase: '#0a0a0f',
          fontFamily: "'Iowan Old Style', 'Palatino Linotype', Palatino, 'Songti SC', serif",
          fontSize: 17,
          lineHeight: 1.7,
        },
      }}
    >
      <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
        <Content style={{ maxWidth: 720, margin: '0 auto', padding: '72px 24px 96px' }}>
          <Paragraph style={{ color: '#8ab4ff', marginBottom: 12 }}>
            Android SO 执行轨迹数据库
          </Paragraph>
          <Title style={{ fontWeight: 650, marginTop: 0 }}>SO Trace Database</Title>
          <Paragraph style={{ fontSize: 18 }}>
            SO Trace Database 是面向 Android 平台 SO（共享库）逆向分析的执行轨迹存储与查询数据库。它把指令、内存写入、寄存器、调用和线程事件存下来，再按地址、步号和线程查回去。
          </Paragraph>
          <Paragraph>
            SO 二进制本身只能看到静态指令和写进文件的常量。一次执行里才会出现的分支、内存写入和寄存器值，并不写在这份 .so 里。只打开二进制会漏掉这些行为。这个数据库解决的就是这件事：把采集到的运行时记录存住，并在分析时检索出来。
          </Paragraph>
          <Card title="产品边界" style={{ margin: '28px 0' }}>
            <Paragraph style={{ marginBottom: 0 }}>
              它不是 trace 采集工具，不替代 Frida、Pin 或 DynamoRIO。它也不是符号执行框架，不做自动漏洞检测。采集仍由现有工具完成，符号执行仍由专门的分析器完成。这里只做轨迹的存储和查询。
            </Paragraph>
          </Card>
          <Paragraph>
            对外发布的是单进程 sotrace-server，配套的 sotrace 命令行走同一条导入和查询路径。backend/ 下的 FastAPI 不是发布入口。
          </Paragraph>
          <Card title="怎么用" style={{ marginBottom: 28 }}>
            <Paragraph>
              Linux x86_64 复制下面这段。它下载已发布的 sotrace-linux-x86_64，并把它当成可执行的 sotrace。存一条轨迹用 trace-save，再把它查出来用 query。
            </Paragraph>
            <pre
              style={{
                margin: 0,
                padding: 16,
                overflowX: 'auto',
                background: '#12141c',
                borderRadius: 8,
                fontSize: 14,
                lineHeight: 1.6,
              }}
            >{`curl -fsSL -o sotrace https://github.com/android-security-engineer/so-trace-database/releases/download/v0.1.0/sotrace-linux-x86_64
chmod +x sotrace
./sotrace --help`}</pre>
          </Card>
          <Card title="这台机器上的写入吞吐" style={{ marginBottom: 28 }}>
            <Paragraph>
              下面两个数是本机 release 二进制的样本中位数，不是可移植的 SLA。内存导入和耐久落盘是两条分开的速率。
            </Paragraph>
            <Paragraph>
              内存里的 TraceEngine::feed_events：6445831 条/秒。这是 5 次试验 events_per_sec 的中位数，导入时不 fsync。
            </Paragraph>
            <Paragraph style={{ marginBottom: 0 }}>
              含持久化的耐久写入：3617370 条/秒。这是 3 次试验 ingest_events_sec 的中位数，每次写入 200000 条并落盘。
            </Paragraph>
          </Card>
          <Alert
            type="warning"
            showIcon
            message="这些目标还没有验收"
            description="相对原始文本 10 倍压缩、单次不少于 10 亿条记录、单个数据库不少于 100GB，以及 SPEC §6.2 的查询延迟，都还不是已经验收的结果，也不能当成 SLA。这一版是一个 sotrace-server 进程，不含微服务拆分。"
          />
        </Content>
      </Layout>
    </ConfigProvider>
  )
}
