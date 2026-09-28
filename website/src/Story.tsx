import { useState } from 'react'
import { Button } from 'antd'

const RUNS = [
  { name: '这一份 trace', line: 'x0 = 第一次返回值' },
  { name: '另一份 trace', line: 'x0 = 下一次返回值' },
] as const

export default function Story() {
  const [index, setIndex] = useState(0)
  const run = RUNS[index]

  return (
    <section className="band band-rule" id="story">
      <div className="story-head">
        <h2>纯文本日志怎么变成可查询的记录</h2>
        <Button type="primary" onClick={() => setIndex((n) => (n + 1) % RUNS.length)}>
          换成另一份 trace
        </Button>
      </div>
      <svg className="story-svg" viewBox="0 0 960 920" role="img" aria-label="纯文本日志变成结构化数据库">
        <text x="24" y="32" fill="#1c2430" fontSize="18">
          {index === 0 ? '现在看的是这一份 trace' : '现在看的是另一份 trace'}
        </text>

        <rect x="24" y="52" width="912" height="180" rx="8" fill="#1c2430" />
        <text x="48" y="92" fill="#e7eee9" fontSize="20">原来的输出</text>
        <text x="48" y="128" fill="#e2a06a" fontSize="20">VMP 加密的 SO，trace 出来是纯文本</text>
        <text x="48" y="164" fill="#c9d4cc" fontSize="16">pc=0x1000 bl</text>
        <text x="48" y="190" fill="#c9d4cc" fontSize="16">mem write 0x2000</text>
        <text x="280" y="190" fill="#c9d4cc" fontSize="16">{run.line}</text>
        <text x="520" y="164" fill="#8ea096" fontSize="16">要检索和分析不太方便</text>

        <rect x="24" y="252" width="912" height="170" rx="8" fill="#ffffff" stroke="#d5ddd8" />
        <text x="48" y="292" fill="#1c2430" fontSize="20">拆成结构化记录</text>
        <text x="48" y="328" fill="#0e6b5c" fontSize="18">同一份日志拆成指令、内存和寄存器</text>
        <rect x="48" y="348" width="250" height="52" rx="6" fill="#eef3f0" />
        <text x="64" y="380" fill="#1c2430" fontSize="16">指令：执行到了哪一条</text>
        <rect x="318" y="348" width="250" height="52" rx="6" fill="#eef3f0" />
        <text x="334" y="380" fill="#1c2430" fontSize="16">内存：写下了什么</text>
        <rect x="588" y="348" width="310" height="52" rx="6" fill="#1c2430" />
        <text x="604" y="380" fill="#e2a06a" fontSize="16">寄存器：{run.line}</text>

        <path className="story-flow" d="M80 442 H880" />
        <g className="story-packet">
          <rect x="80" y="430" width="420" height="36" rx="18" fill="#0e6b5c" />
          <text x="96" y="454" fill="#ffffff" fontSize="16">纯文本日志正在被整理进数据库</text>
        </g>

        <rect x="24" y="490" width="912" height="160" rx="8" fill="#f7fbf8" stroke="#0e6b5c" />
        <text x="48" y="530" fill="#1c2430" fontSize="20">存成可查询的数据库</text>
        <text x="48" y="566" fill="#0e6b5c" fontSize="18">这些记录被存进数据库，之后可以按条件查</text>
        <text x="48" y="602" fill="#1c2430" fontSize="16">trace-save 收下{run.name}，不再只留一份纯文本</text>

        <rect x="24" y="670" width="912" height="220" rx="8" fill="#0e6b5c" />
        <text x="48" y="714" fill="#e7eee9" fontSize="20">再查一条出来</text>
        <text x="48" y="752" fill="#ffffff" fontSize="20">query 把已经存好的一条记录读出来</text>
        <rect x="48" y="776" width="460" height="80" rx="6" fill="#146e60" />
        <text x="64" y="808" fill="#d5eee6" fontSize="14">读出来的是{run.name}</text>
        <text className="shown-fact" x="64" y="838" fill="#ffffff" fontSize="20">{run.line}</text>
      </svg>
    </section>
  )
}
