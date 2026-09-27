# Ghidra Script Manager 使用说明

## Script Manager 模式（推荐）

### Java 版本（SoTraceScript.java）

1. 复制 `SoTraceScript.java` 到 Ghidra 脚本目录：
   ```
   ~/.ghidra/.ghidra_<version>/scripts/
   ```
   或任意在 Script Manager 的搜索路径中的目录。

2. 打开 Ghidra → 打开目标 SO 文件 → 等待分析完成

3. 菜单 **Window → Script Manager**，搜索 `SoTraceScript`，双击运行

4. 在弹出对话框中输入 sotrace-server URL（如 `http://192.168.1.83:3000`），留空则保存为 JSONL 文件

### Python 版本（sotrace_script.py，Jython 2.7）

1. 复制 `sotrace_script.py` 到同样的脚本目录

2. Script Manager 搜索 `sotrace_script`，双击运行

3. 操作与 Java 版本相同

---

## 无头（Headless）模式 via PyGhidra

适合 CI/批量分析场景，无需 GUI。

```bash
# 安装
pip install pyghidra

# 运行
python sotrace-ghidra.py \
    --ghidra-home /opt/ghidra \
    --server http://192.168.1.83:3000 \
    /path/to/libnative.so
```

输出示例：
```
[sotrace] Starting Ghidra JVM from /opt/ghidra …
[sotrace] Opening /path/to/libnative.so …
[sotrace] Collected 12345 instructions, 876 calls
[sotrace] trace_id=42
[sotrace] Races: http://192.168.1.83:3000/api/v1/traces/42/analyze/threads/races
```

---

## 分析 API

上传后通过 HTTP 访问分析结果：

| 端点 | 说明 |
|------|------|
| `GET /api/v1/traces/{id}/analyze/threads/races` | 竞态检测 |
| `GET /api/v1/traces/{id}/analyze/threads/deadlocks` | 死锁检测 |
| `GET /api/v1/traces/{id}/analyze/threads/contentions` | 锁争用 |
| `GET /api/v1/traces/{id}/analyze/threads/critical-sections` | 临界区分析 |
| `GET /api/v1/traces/{id}/analyze/threads/jni-boundary` | JNI 边界统计 |
| `GET /api/v1/traces/{id}/analyze/threads/scheduling` | 调度分析 |
