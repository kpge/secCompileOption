# secCompileCheck (scc) — ELF 安全编译选项检查工具

参考 [checksec](https://github.com/slimm609/checksec) 的检测逻辑,使用 Go 重写的二进制加固选项检查器。**零第三方依赖**,只用 Go 标准库(`debug/elf`),单二进制交叉编译到任意平台。

> **致谢**:各检测项的判定规则派生自 [checksec](https://github.com/slimm609/checksec)(BSD License,Copyright (c) 2014-2022 Brian Davis、2013 Robin David、2009-2011 Tobias Klein),许可条款见 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。

## 检测项

| 检测项 | 判定依据 | 加固方法 |
|---|---|---|
| **RELRO** | `PT_GNU_RELRO` 段 + `DT_BIND_NOW` / `DF_BIND_NOW` / `DF_1_NOW` | `-Wl,-z,relro,-z,now` |
| **Stack Canary** | `__stack_chk_fail` / `__stack_chk_guard` / Intel ICC cookie 符号 | `-fstack-protector-strong` |
| **NX** | `PT_GNU_STACK` 是否带 `PF_X` | `-z noexecstack` |
| **PIE** | `ET_DYN` + `DF_1_PIE` / `PT_INTERP`(区分 PIE、Static-PIE、DSO、ET_EXEC) | `-fPIE -pie` |
| **RPATH / RUNPATH** | `DT_RPATH` / `DT_RUNPATH`,逐条目评估:相对路径、空条目、world-writable 目录为危险 | 避免使用,或 `-Wl,-rpath,$ORIGIN/...` |
| **Symbols** | 是否保留 `.symtab` | `-s` / `strip` |
| **FORTIFY** | 二进制引用的 `_chk` 加固函数 vs 同名未加固函数(`_FORTIFY_SOURCE`) | `-D_FORTIFY_SOURCE=2 -O2` |

对**节头被剥离的 stripped 二进制**,通过 `PT_DYNAMIC`/`PT_LOAD` 程序头直接解析动态符号表,检测依然有效(这是与简单 readelf 封装的本质区别)。

## 安装与构建

```bash
go build -o scc ./cmd/scc
```

交叉编译(在任意平台产出任意目标平台二进制):

```bash
GOOS=linux  GOARCH=amd64 go build -o scc-linux-amd64 ./cmd/scc
GOOS=linux  GOARCH=arm64 go build -o scc-linux-arm64 ./cmd/scc
GOOS=windows GOARCH=amd64 go build -o scc.exe ./cmd/scc
```

## 使用

```
scc <command> [flags] <target>

命令:
  file <binary>          检查单个 ELF 文件
  dir <directory>        检查目录下所有 ELF(-recursive 递归)
  list <file>            检查列表文件中的路径(每行一个,# 开头为注释)
  version                版本

选项:
  -format string         输出格式:table(默认)/ json / csv / xml
  -libc string           指定 libc 路径(FORTIFY 分析)
  -no-color              关闭彩色输出(非终端自动关闭)
```

flag 可放在目标参数前或后(`scc file x -format json` 与 `scc file -format json x` 等价)。

### 示例

```bash
$ scc file /usr/bin/ls
+------------+--------------+------------+-------------+----------+------------+--------------------+---------+-----------+-------------+
| RELRO      | Canary       | NX         | PIE         | RPATH    | RUNPATH    | Symbols            | FORTIFY | Fortified | Fortifiable |
+------------+--------------+------------+-------------+----------+------------+--------------------+---------+-----------+-------------+
| Full RELRO | Canary found | NX enabled | PIE enabled | No RPATH | No RUNPATH | No symbols (stripped) | Yes    | 3         | 6           |
+------------+--------------+------------+-------------+----------+------------+--------------------+---------+-----------+-------------+

$ scc dir /usr/bin -recursive -format json > report.json
$ scc file ./mybin -format csv
$ scc list binaries.txt -format xml
```

### 退出码(CI 集成)

| 退出码 | 含义 |
|---|---|
| 0 | 所有检查通过(或目标目录无 ELF) |
| 1 | 用法/IO 错误 |
| 2 | 至少一个二进制存在 bad 项(RELRO/Canary/NX/PIE/RPATH 任一失败) |

```bash
scc dir ./build && echo "hardening OK"
```

## 输出格式

- **table** — 对齐表格,good=绿 / warn=黄 / bad=红(仅终端)
- **json** — `[{name, checks: {key: {value, status}}}]`,可直接进 jq
- **csv** — 首行 `name,relro,canary,...`
- **xml** — `<secCompileCheck><file name=...><check key=... status=...>value</check>`

## 与 checksec 的差异

- 只实现文件/目录/列表检查;进程(`--proc`)、内核(`--kernel`)检测依赖 Linux `/proc` 与 kconfig,未包含
- FORTIFY 采用编译器固定的可加固函数集(gcc/clang builtins),不依赖宿主机 libc 文件,因此跨架构/chroot 扫描结果一致
- RPATH/RUNPATH 增加了逐条目风险评估(相对路径/空条目/world-writable 目录标红)
- 零依赖、单二进制;checksec 依赖 readelf、objdump 等 binutils

## 项目结构

```
cmd/scc/             CLI 入口(产物名 scc)
internal/checksec/   各检测项 + 报告聚合(纯库,可复用)
internal/output/     table/JSON/CSV/XML 渲染
internal/elfgen/     合成 ELF 测试样本生成器(测试专用)
testdata/            合成样本 + 真实交叉编译样本
```

## 测试

```bash
go test ./...
```

单元测试覆盖每个检测项的 good/warn/bad 分支;`internal/elfgen` 按加固组合合成最小合法 ELF,无需 Linux 工具链即可回归。真实样本验证:`go build` 交叉编译的 Linux amd64/arm64/386 二进制(PIE、non-PIE、stripped)检测结果与 ELF 头部事实一致。
