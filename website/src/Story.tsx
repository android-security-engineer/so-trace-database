import { useState } from 'react'
import { Button } from 'antd'

const FACTS = ['0x9a4964e7', '0xc0ffee21'] as const

export default function Story() {
  const [index, setIndex] = useState(0)
  const fact = FACTS[index]

  return (
    <section className="band band-rule" id="story">
      <div className="story-head">
        <h2>从打开文件，到执行，再到查回</h2>
        <Button type="primary" onClick={() => setIndex((n) => (n + 1) % FACTS.length)}>
          换成另一条运行时结果
        </Button>
      </div>
      <svg className="story-svg" viewBox="0 0 960 1480" role="img" aria-label="从 SO 到轨迹再到查询">
        <line className="story-flow" x1="36" y1="48" x2="36" y2="1420" />
        <circle className="story-packet" cx="36" cy="48" r="8" />

        <circle cx="36" cy="70" r="14" fill="#0e6b5c" />
        <text x="30" y="75" fill="#fff" fontSize="12">1</text>
        <rect x="72" y="24" width="860" height="180" rx="8" fill="#1c2430" />
        <text x="92" y="56" fill="#e7eee9" fontSize="18">静态字节</text>
        <text x="92" y="82" fill="#8ea096" fontSize="14">文件里能直接看到的内容</text>
        <rect x="92" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="100" y="124" fill="#e2a06a" fontSize="14">7f</text>
        <rect x="152" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="160" y="124" fill="#e2a06a" fontSize="14">45</text>
        <rect x="212" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="220" y="124" fill="#e2a06a" fontSize="14">4c</text>
        <rect x="272" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="280" y="124" fill="#e2a06a" fontSize="14">46</text>
        <rect x="332" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="340" y="124" fill="#c9d4cc" fontSize="14">02</text>
        <rect x="392" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="400" y="124" fill="#c9d4cc" fontSize="14">01</text>
        <rect x="452" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="460" y="124" fill="#c9d4cc" fontSize="14">01</text>
        <rect x="512" y="100" width="52" height="36" rx="4" fill="#2a3544" />
        <text x="520" y="124" fill="#c9d4cc" fontSize="14">00</text>
        <text x="92" y="172" fill="#8ea096" fontSize="14">这是 ELF 头，不是这次运行的结果</text>

        <circle cx="36" cy="276" r="14" fill="#0e6b5c" />
        <text x="30" y="281" fill="#fff" fontSize="12">2</text>
        <rect x="72" y="230" width="860" height="180" rx="8" fill="#f7fbf8" stroke="#c45c26" strokeDasharray="6 4" />
        <text x="92" y="262" fill="#1c2430" fontSize="18">缺失的运行结果</text>
        <text x="92" y="288" fill="#5c6b63" fontSize="14">打开文件看不到这次返回值</text>
        <rect x="92" y="308" width="280" height="64" rx="6" fill="#fff" stroke="#c45c26" />
        <text x="108" y="336" fill="#8ea096" fontSize="14">空位</text>
        <text x="108" y="358" fill="#c45c26" fontSize="18">没有 {fact}</text>
        <text x="400" y="348" fill="#1c2430" fontSize="16">函数还没跑，这个值不存在于 .so</text>

        <circle cx="36" cy="482" r="14" fill="#0e6b5c" />
        <text x="30" y="487" fill="#fff" fontSize="12">3</text>
        <rect x="72" y="436" width="860" height="180" rx="8" fill="#ffffff" stroke="#d5ddd8" />
        <text x="92" y="468" fill="#1c2430" fontSize="18">指令事件</text>
        <text x="92" y="494" fill="#5c6b63" fontSize="14">处理器执行到的那一条指令</text>
        <rect x="92" y="514" width="120" height="64" rx="6" fill="#eef3f0" />
        <text x="108" y="542" fill="#5c6b63" fontSize="13">地址</text>
        <text x="108" y="564" fill="#0e6b5c" fontSize="18">0x1000</text>
        <rect x="228" y="514" width="160" height="64" rx="6" fill="#eef3f0" />
        <text x="244" y="542" fill="#5c6b63" fontSize="13">操作</text>
        <text x="244" y="564" fill="#1c2430" fontSize="18">bl mix</text>
        <path d="M420 546 H520" className="story-flow" />
        <circle className="story-packet" cx="428" cy="546" r="6" />
        <text x="540" y="552" fill="#1c2430" fontSize="16">执行流走到这里，文件本身不会标出</text>

        <circle cx="36" cy="688" r="14" fill="#0e6b5c" />
        <text x="30" y="693" fill="#fff" fontSize="12">4</text>
        <rect x="72" y="642" width="860" height="180" rx="8" fill="#ffffff" stroke="#d5ddd8" />
        <text x="92" y="674" fill="#1c2430" fontSize="18">内存事件</text>
        <text x="92" y="700" fill="#5c6b63" fontSize="14">执行时写进内存的字节</text>
        <rect x="92" y="720" width="90" height="56" rx="6" fill="#1c2430" />
        <text x="104" y="754" fill="#e2a06a" fontSize="16">0x2000</text>
        <rect x="196" y="720" width="48" height="56" rx="4" fill="#0e6b5c" />
        <text x="208" y="754" fill="#fff" fontSize="16">a9</text>
        <rect x="252" y="720" width="48" height="56" rx="4" fill="#0e6b5c" />
        <text x="264" y="754" fill="#fff" fontSize="16">64</text>
        <rect x="308" y="720" width="48" height="56" rx="4" fill="#0e6b5c" />
        <text x="320" y="754" fill="#fff" fontSize="16">49</text>
        <rect x="364" y="720" width="48" height="56" rx="4" fill="#0e6b5c" />
        <text x="376" y="754" fill="#fff" fontSize="16">9a</text>
        <text x="440" y="754" fill="#1c2430" fontSize="16">这次写入不在静态字节里</text>

        <circle cx="36" cy="894" r="14" fill="#0e6b5c" />
        <text x="30" y="899" fill="#fff" fontSize="12">5</text>
        <rect x="72" y="848" width="860" height="180" rx="8" fill="#ffffff" stroke="#d5ddd8" />
        <text x="92" y="880" fill="#1c2430" fontSize="18">寄存器事件</text>
        <text x="92" y="906" fill="#5c6b63" fontSize="14">执行结束后寄存器里的值</text>
        <rect x="92" y="926" width="200" height="70" rx="6" fill="#1c2430" />
        <text x="108" y="954" fill="#8ea096" fontSize="14">x0</text>
        <text x="108" y="980" fill="#e2a06a" fontSize="22">{fact}</text>
        <text x="320" y="966" fill="#1c2430" fontSize="16">这就是那次调用的返回值，打开 .so 看不到</text>

        <circle cx="36" cy="1100" r="14" fill="#0e6b5c" />
        <text x="30" y="1105" fill="#fff" fontSize="12">6</text>
        <rect x="72" y="1054" width="860" height="180" rx="8" fill="#f7fbf8" stroke="#0e6b5c" />
        <text x="92" y="1086" fill="#1c2430" fontSize="18">存入轨迹</text>
        <text x="92" y="1112" fill="#5c6b63" fontSize="14">trace-save 把这三件事记下来</text>
        <rect x="92" y="1132" width="220" height="36" rx="4" fill="#fff" stroke="#d5ddd8" />
        <text x="104" y="1156" fill="#1c2430" fontSize="14">指令 0x1000</text>
        <rect x="92" y="1176" width="220" height="36" rx="4" fill="#fff" stroke="#d5ddd8" />
        <text x="104" y="1200" fill="#1c2430" fontSize="14">内存 0x2000</text>
        <rect x="330" y="1132" width="280" height="80" rx="6" fill="#0e6b5c" />
        <text x="346" y="1164" fill="#d5eee6" fontSize="14">寄存器</text>
        <text x="346" y="1194" fill="#fff" fontSize="22">{fact}</text>
        <text x="630" y="1176" fill="#1c2430" fontSize="16">三条记录进同一条时间线</text>

        <circle cx="36" cy="1306" r="14" fill="#0e6b5c" />
        <text x="30" y="1311" fill="#fff" fontSize="12">7</text>
        <rect x="72" y="1260" width="860" height="190" rx="8" fill="#0e6b5c" />
        <text x="92" y="1296" fill="#e7eee9" fontSize="18">查询读回</text>
        <text x="92" y="1322" fill="#d5eee6" fontSize="14">query 从轨迹里取出其中一件</text>
        <rect x="92" y="1344" width="360" height="76" rx="6" fill="#146e60" />
        <text x="108" y="1374" fill="#d5eee6" fontSize="14">已存轨迹里的记录</text>
        <text className="shown-fact" x="108" y="1404" fill="#ffffff" fontSize="26">{fact}</text>
        <text x="480" y="1388" fill="#e7eee9" fontSize="16">查回的是运行时结果，不是文件里的常量</text>
      </svg>
    </section>
  )
}
