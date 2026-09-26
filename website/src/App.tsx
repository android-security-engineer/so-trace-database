export default function App() {
  return (
    <main style={{ maxWidth: 880, margin: '0 auto', padding: '64px 24px 96px' }}>
      <p style={{ color: '#8ab4ff', letterSpacing: '0.08em', fontSize: 13, marginBottom: 16 }}>
        Android SO 执行轨迹数据库
      </p>
      <h1 style={{ fontSize: 44, lineHeight: 1.2, fontWeight: 650, marginBottom: 20 }}>
        SO Trace Database
      </h1>
      <p style={{ fontSize: 18, lineHeight: 1.7, color: '#c9d1d9', marginBottom: 28 }}>
        SO Trace Database 是面向 Android 平台 SO（共享库）逆向分析的执行轨迹数据库。它存储并查询指令、内存、寄存器、调用和线程事件，不替代 Frida、Pin 或 DynamoRIO 的采集，也不做符号执行。
      </p>
      <p style={{ fontSize: 20, lineHeight: 1.6, marginBottom: 40 }}>
        限量单进程版本现在可以发布。没有日历发布日。
      </p>

      <section style={{ marginBottom: 36 }}>
        <h2 style={{ fontSize: 22, marginBottom: 12 }}>发布入口</h2>
        <p style={{ lineHeight: 1.75, color: '#c9d1d9' }}>
          发布入口是单进程 sotrace-server。CLI 和 MCP 是配套入口，和服务器一样把事件送进同一条导入路径。backend/ 下的 FastAPI 不是发布入口。
        </p>
      </section>

      <section style={{ marginBottom: 36 }}>
        <h2 style={{ fontSize: 22, marginBottom: 12 }}>怎样启动这一版</h2>
        <p style={{ lineHeight: 1.75, color: '#c9d1d9', marginBottom: 12 }}>
          进程启动时设置口令 SOTRACE_AUTH_TOKEN、数据目录 SOTRACE_DATA_DIR，以及绑定地址 SOTRACE_BIND。未设置口令时服务器拒绝启动。导入和指令查询要带与该口令一致的 Authorization: Bearer。健康检查不需要凭证。
        </p>
        <p style={{ lineHeight: 1.75, color: '#c9d1d9' }}>
          导入只留在内存里，直到调用保存成功才落盘。导入返回成功不等于崩溃之后还能读回。保存成功之后，新进程打开同一数据目录才能读到这批事件。
        </p>
      </section>

      <section>
        <h2 style={{ fontSize: 22, marginBottom: 12 }}>还不能当成已经完成</h2>
        <p style={{ lineHeight: 1.75, color: '#c9d1d9' }}>
          以下尚未验收，不能对外说已经完成：VISION 的 10x 压缩、单次不少于 10 亿条记录、单个数据库不少于 100GB、SPEC §6.2 的查询延迟（不是已验收的 SLA），以及微服务拆分。这一版就是一个 sotrace-server 进程。
        </p>
      </section>
    </main>
  )
}
