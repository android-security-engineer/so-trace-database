# IDA Pro 插件使用说明

## 安装（GUI 插件）

将 `sotrace-ida/` 整个目录复制到 IDA 插件目录：

```bash
# IDA 全局插件目录
cp -r plugins/sotrace-ida ~/.idapro/plugins/sotrace_ida

# 或 IDA 安装目录下的 plugins/
cp -r plugins/sotrace-ida /opt/ida/plugins/sotrace_ida
```

重启 IDA Pro，插件自动加载。日志窗口应看到：
```
[sotrace] loaded — press Ctrl+Shift+T to upload
```

---

## GUI 使用

1. 用 IDA 打开 SO 文件，等待自动分析完成（Auto Analysis）

2. 按 **Ctrl+Shift+T**（或菜单 **Edit → Plugins → Upload to sotrace-server**）

3. 在弹窗中输入 sotrace-server URL（如 `http://192.168.1.83:3000`）
   - 留空 → 弹出保存文件对话框，将 trace 保存为 JSONL

4. 上传完成后弹窗显示：
   ```
   sotrace upload done!
   trace_id = 42
   instructions = 12345
   calls = 876

   Races: http://192.168.1.83:3000/api/v1/traces/42/analyze/threads/races
   ```

---

## IDAPython 脚本内使用

在 IDA 的 **File → Script command** 或 `.idc` / `.py` 脚本中：

```python
import sys
sys.path.insert(0, "/path/to/plugins/sotrace-ida")

from sotrace_ida.analyzer import analyze_static
from sotrace_ida.client import SoTraceClient

envelope = analyze_static()
client = SoTraceClient("http://192.168.1.83:3000")
trace_id = client.import_trace(envelope)
print(f"trace_id={trace_id}")

# 分析
result = client.get_analysis(trace_id, "contentions")
print(result)
```

---

## 无头模式（idat64 批量分析）

适合 CI 或批量分析场景：

```bash
python plugins/sotrace-ida/examples/headless_analysis.py \
    --idat /opt/ida/idat64 \
    --server http://192.168.1.83:3000 \
    /path/to/libnative.so

# 保存为文件
python plugins/sotrace-ida/examples/headless_analysis.py \
    --idat /opt/ida/idat64 \
    --output /tmp/trace.jsonl \
    /path/to/libnative.so
```

---

## 分析 API

| 端点 | 适合静态分析 |
|------|-------------|
| `contentions` — 锁争用 | ✓ |
| `critical-sections` — 临界区 | ✓ |
| `jni-boundary` — JNI 边界 | ✓ |
| `lifecycle` — 线程生命周期 | ✓ |
| `states` — 线程状态 | ✓ |
| `races` — 竞态（需运行时数据） | 有限 |
| `deadlocks` — 死锁（需运行时数据） | 有限 |

> **注意**：IDA 为静态分析工具，`thread_id` 固定为 1，`branch_taken` 固定为 false。
> 基于同步事件的检测维度（races/deadlocks）需配合运行时工具（如 Frida/GDB/unidbg）数据。
