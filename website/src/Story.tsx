import { useState } from 'react'
import { Button } from 'antd'

const FACTS = ['0x9a4964e7', '0xc0ffee21'] as const

export default function Story() {
  const [index, setIndex] = useState(0)
  const fact = FACTS[index]

  return (
    <section className="band band-rule" id="story">
      <div className="story-head">
        <h2>二进制里没有的结果，执行之后才能查到</h2>
        <Button
          type="primary"
          onClick={() => setIndex((n) => (n + 1) % FACTS.length)}
        >
          换成另一条运行时结果
        </Button>
      </div>
      <svg className="story-svg" viewBox="0 0 880 250" role="img" aria-label="从 SO 到轨迹再到查询">
        <rect x="16" y="36" width="210" height="170" rx="8" fill="#1c2430" />
        <text x="32" y="68" fill="#e7eee9" fontSize="16">libreveal.so</text>
        <text x="32" y="98" fill="#8ea096" fontSize="13">静态字节里</text>
        <text x="32" y="122" fill="#e2a06a" fontSize="18" fontFamily="ui-monospace, monospace">没有 {fact}</text>
        <text x="32" y="156" fill="#8ea096" fontSize="13">这个返回值只在</text>
        <text x="32" y="176" fill="#8ea096" fontSize="13">函数跑完才出现</text>

        <path className="story-flow" d="M240 120 H360" />
        <circle className="story-packet" cx="248" cy="120" r="7" />
        <text x="268" y="104" fill="#0e6b5c" fontSize="13">trace-save</text>

        <rect x="370" y="36" width="180" height="170" rx="8" fill="#f7fbf8" stroke="#0e6b5c" />
        <text x="386" y="68" fill="#1c2430" fontSize="16">轨迹库</text>
        <text x="386" y="104" fill="#5c6b63" fontSize="13">已存入寄存器</text>
        <text x="386" y="136" fill="#0e6b5c" fontSize="20" fontFamily="ui-monospace, monospace">{fact}</text>

        <path className="story-flow story-flow-late" d="M560 120 H660" />
        <circle className="story-packet story-packet-late" cx="568" cy="120" r="7" />
        <text x="588" y="104" fill="#0e6b5c" fontSize="13">query</text>

        <rect x="670" y="36" width="190" height="170" rx="8" fill="#0e6b5c" />
        <text x="686" y="68" fill="#e7eee9" fontSize="16">查回的结果</text>
        <text className="shown-fact" x="686" y="128" fill="#ffffff" fontSize="22" fontFamily="ui-monospace, monospace">{fact}</text>
      </svg>
    </section>
  )
}
