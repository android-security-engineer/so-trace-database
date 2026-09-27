[简体中文](README.zh-CN.md)

# SO Trace Database

SO Trace Database is a store-and-query database for Android SO (shared-library) execution traces. It exists so an analyst can recover runtime behavior the SO binary itself does not contain: branches, memory writes, register values, calls, and thread events that appear only while the library runs.

It is not a trace collector, and it does not replace Frida, Pin, or DynamoRIO. It is not a symbolic-execution framework.

## Install

Linux x86_64. This downloads the published `sotrace` command-line tool and prints its usage:

```sh
curl -fsSL -o sotrace https://github.com/android-security-engineer/so-trace-database/releases/download/v0.1.0/sotrace-linux-x86_64
chmod +x sotrace
./sotrace --help
```

`trace-save` stores a trace. `query` reads it back.

To build the same CLI from this tree instead:

```sh
cargo build --release -p sotrace-cli
./target/release/sotrace --help
```
