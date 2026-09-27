[English](README.md)

# SO Trace Database

SO Trace Database 是面向 Android SO（共享库）执行轨迹的存储与查询数据库。分析人员用它找回 SO 二进制本身没有的运行时行为：只有库真正跑起来才会出现的分支、内存写入、寄存器值、调用和线程事件。

它不是 trace 采集工具，也不替代 Frida、Pin 或 DynamoRIO。它不是符号执行框架。

## 安装

Linux x86_64。下面这段会下载已发布的 `sotrace` 命令行并打印用法：

```sh
curl -fsSL -o sotrace https://github.com/android-security-engineer/so-trace-database/releases/download/v0.1.0/sotrace-linux-x86_64
chmod +x sotrace
./sotrace --help
```

`trace-save` 把轨迹存进去。`query` 再把它查出来。

也可以在本仓库里自己编译同一条命令：

```sh
cargo build --release -p sotrace-cli
./target/release/sotrace --help
```
