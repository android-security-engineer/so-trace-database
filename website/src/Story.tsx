import { useState } from 'react'
import { Button } from 'antd'

const RUNS = [
  { name: '第一次运行', fact: '0x9a4964e7' },
  { name: '另一次运行', fact: '0xc0ffee21' },
] as const

export default function Story() {
  const [index, setIndex] = useState(0)
  const run = RUNS[index]

  return (
    <section className="band band-rule" id="story">
      <div className="story-head">
        <h2>这张图在讲什么</h2>
        <Button type="primary" onClick={() => setIndex((n) => (n + 1) % RUNS.length)}>
          换成另一条运行时结果
        </Button>
      </div>
      <svg className="story-svg" viewBox="0 0 960 980" role="img" aria-label="从 SO 到轨迹再到查询">
        <text x="24" y="36" fill="#1c2430" fontSize="18">
          {index === 0 ? '现在看的是这一次运行' : '现在看的是另一次运行'}
        </text>
        <text x="280" y="36" fill="#0e6b5c" fontSize="18">示例返回值 {run.fact}</text>

        <rect x="24" y="60" width="912" height="150" rx="8" fill="#1c2430" />
        <text x="48" y="100" fill="#e7eee9" fontSize="20">1. 打开文件</text>
        <text x="48" y="138" fill="#e2a06a" fontSize="22">打开这个文件看不到程序跑完之后的结果</text>
        <text x="48" y="174" fill="#8ea096" fontSize="16">.so 里只有写死的内容，没有这次跑出来的返回值</text>

        <rect x="24" y="230" width="912" height="200" rx="8" fill="#ffffff" stroke="#d5ddd8" />
        <text x="48" y="270" fill="#1c2430" fontSize="20">2. 程序跑起来</text>
        <text x="48" y="308" fill="#0e6b5c" fontSize="22">程序一跑才会产生指令、内存和寄存器记录</text>
        <rect x="48" y="332" width="260" height="70" rx="6" fill="#eef3f0" />
        <text x="64" y="362" fill="#5c6b63" fontSize="14">指令</text>
        <text x="64" y="386" fill="#1c2430" fontSize="16">执行到了哪一条</text>
        <rect x="328" y="332" width="260" height="70" rx="6" fill="#eef3f0" />
        <text x="344" y="362" fill="#5c6b63" fontSize="14">内存</text>
        <text x="344" y="386" fill="#1c2430" fontSize="16">写下了什么字节</text>
        <rect x="608" y="332" width="290" height="70" rx="6" fill="#1c2430" />
        <text x="624" y="362" fill="#8ea096" fontSize="14">寄存器</text>
        <text x="624" y="388" fill="#e2a06a" fontSize="18">{run.fact}</text>

        <path className="story-flow" d="M80 450 H880" />
        <g className="story-packet">
          <rect x="80" y="438" width="360" height="36" rx="18" fill="#0e6b5c" />
          <text x="96" y="462" fill="#ffffff" fontSize="16">运行结果正在被送进数据库</text>
        </g>

        <rect x="24" y="500" width="912" height="170" rx="8" fill="#f7fbf8" stroke="#0e6b5c" />
        <text x="48" y="540" fill="#1c2430" fontSize="20">3. 存起来</text>
        <text x="48" y="578" fill="#0e6b5c" fontSize="22">这些记录被存进数据库</text>
        <text x="48" y="616" fill="#1c2430" fontSize="16">trace-save 把指令、内存和寄存器放进同一条轨迹</text>
        <text x="48" y="646" fill="#5c6b63" fontSize="16">{run.name} 的返回值 {run.fact} 也在里面</text>

        <rect x="24" y="690" width="912" height="250" rx="8" fill="#0e6b5c" />
        <text x="48" y="734" fill="#e7eee9" fontSize="20">4. 以后再查</text>
        <text x="48" y="776" fill="#ffffff" fontSize="22">查询把其中一条读出来</text>
        <text x="48" y="814" fill="#d5eee6" fontSize="16">query 读的是已经存好的轨迹，不是再去翻 .so 文件</text>
        <rect x="48" y="840" width="420" height="72" rx="6" fill="#146e60" />
        <text x="64" y="870" fill="#d5eee6" fontSize="14">读出来的是{run.name}</text>
        <text className="shown-fact" x="64" y="896" fill="#ffffff" fontSize="22">{run.fact}</text>
      </svg>
    </section>
  )
}
