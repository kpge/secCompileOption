# 发布流程规范

本文件定义 secCompileCheck (scc) 的正式发布流程、版本约束、发布前置条件、标准发布步骤和发布后验证要求。**发布由人工手动触发**,不存在任何自动发布路径。

- 流程规范:本文件
- 发布执行:`.github/workflows/release.yml`(唯一正式发布入口)
- CI 门禁细节:`.github/workflows/ci.yml`

## 1. 目标

发布流程需要满足:

- 发布动作可复现:任何人按本文档操作得到相同结果
- 版本号与产物命名一致:产物文件名、release notes、`scc version` 三处的版本一致
- 发布说明与真实产物一致:下载链接指向实际存在的资产
- 发布前后都可验证:产物有 SHA-256 校验,发布后有验证清单
- 测试先行:tag 永远发不出未经 CI 门禁的构建

## 2. 适用范围

本规范适用于:

- 版本发布准备
- tag 创建
- release 产物构建与上传
- 发布后验证

不适用于 CI 日常验证(见 `ci.yml` 的每日/推送触发)。

## 3. 权威边界

- 正式发布流程以本文件为准
- 发布用 workflow 的实际行为以 `.github/workflows/release.yml` 为准;两者不一致时,先改代码再改文档,同步合入
- 本仓库发布到两个渠道:GitHub Release(构建侧)与 GitCode Release(同步侧),见 §6.6;无 PyPI/npm/Homebrew 等分发链路(如未来增加,必须同步更新本规范)
- 默认推送远端为 GitCode(`origin` → https://gitcode.com/SmartCICD/secCompileOption.git);GitHub 作为备用远端(远端名 `github`),两者必须保持同一 tag 指向同一 commit

## 4. 版本规则

项目版本遵循语义化版本:

```text
vMAJOR.MINOR.PATCH[-PRERELEASE]
```

示例:`v1.0.0`、`v1.0.1`、`v1.1.0`、`v2.0.0`、`v2.0.0-beta.1`

其中 `PRERELEASE` 只允许 `alpha.N`、`beta.N`、`rc.N` 形式,`N` 为非负整数且不能带前导零。workflow_dispatch 的 `version` 输入在第一阶段(`Validate version` job)按此白名单校验,不通过则整个 workflow 终止,不会创建任何 tag 或 release。

发布时必须保证:

- git tag 与 release tag 一致
- 产物文件名中的版本与 tag 一致(如 `scc-v1.0.1-linux-amd64`)
- 二进制内嵌版本(`scc version` 输出)与 tag 一致——由构建参数 `-ldflags "-X main.version=<tag>"` 注入,linux/amd64 构建有 `grep -F` 冒烟断言
- 版本号只进不退:已发布的版本号不得重用(校验 job 会拒绝已存在的 tag)

版本号何时升级:

- `PATCH`:bug 修复、检测精度改进,无新检测项
- `MINOR`:新增检测项、新增输出格式/CLI 命令
- `MAJOR`:检测语义变更(如 RPATH 判定标准变化导致既有合规结论反转)

## 5. 发布前置条件

正式发布前必须满足:

- 目标改动已合入 `main`
- `main` 上最新一次 CI 全绿(Actions → CI)
- 本地最低验证已通过(见 §6.2)
- 无未解决的 blocker 级 issue
- 发版人具有仓库 write 权限(workflow_dispatch 触发和 tag 推送都需要)
- 若发布预发布版本(`-beta.N` 等),确认接受 GitHub 将其标记为 pre-release

首次发布前的一次性前提(已就绪,列出供重建时参考):

- `release.yml` 的 `permissions: contents: write`(仓库 Actions 允许 GITHUB_TOKEN 创建 Release)
- `cmd/scc/main.go` 的 `version` 是变量而非常量(支持 `-ldflags -X` 注入)

## 6. 标准发布流程

推荐路径是 **workflow_dispatch 手动触发**;直接推 tag 也可触发(见 §6.6),但手动触发是首选,因为它带版本白名单校验和 tag 冲突预检。

### 6.1 获取最新主线

```bash
git checkout main
git pull origin main
git log --oneline -3   # 确认要发布的提交在顶部
```

### 6.2 最低发布前验证

```bash
go vet ./...
go test ./... -count=1
go build -buildmode=pie -trimpath -ldflags="-s -bindnow" -o scc ./cmd/scc
./scc version
```

如发布涉及检测行为变更,再跑一次端到端套件(需 Linux):

```bash
bash tests/test-scc.sh
```

### 6.3 触发发布 workflow

通过 `gh` CLI(推荐,可跟踪):

```bash
gh workflow run release.yml -f version=vX.Y.Z
gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

或通过网页:Actions → Release → Run workflow → 填入 `vX.Y.Z` → Run。

**workflow 内部流程**(发布人应了解,便于排障):

1. `Validate version`:白名单校验版本格式;检查 tag 不存在。未通过则终止
2. `Test`(Go 1.24/1.25):vet + 单元测试 + gofmt。失败则终止
3. `Release`(6 平台并行):交叉编译 linux/amd64+arm64+386、darwin/amd64+arm64、windows/amd64,产物名 `scc-<tag>-<os>-<arch>[.exe]`,每个附 `.sha256`
4. `Publish`:汇总校验全部 SHA-256 → 生成 `checksums.txt` 与 release notes → 在当前 commit 上创建 tag → 创建 GitHub Release 并上传全部资产

全部 job 完成即发布完成,全程约 3~5 分钟。

### 6.4 发布失败的处理

- 在 `Validate version` 失败:版本号格式或 tag 冲突。修正版本号重新触发即可,无副作用
- 在 `Test` 失败:主线不可发布。修复后重新触发
- 在 `Release`/`Publish` 失败:tag 可能已创建但 Release 未完成。修复 workflow 后重跑;`Publish` 是幂等的——若 Release 已存在且资产完全一致会自动跳过,资产不一致会拒绝覆盖并报错(防止换产物)
- **禁止**用删 tag 重打的方式"修复"已对外可见的发布,除非确认无人下载(如发布后几分钟内发现致命错误);此时先删 Release 再删 tag,并在重发前修复问题

### 6.5 发布后验证

发布完成后,发布人必须逐项确认:

- [ ] Release 页面存在且非 draft:https://github.com/kpge/secCompileOption/releases
- [ ] 资产清单完整:6 个平台二进制 + `checksums.txt`,共 7 个
- [ ] 产物文件名中的版本与 tag 一致
- [ ] 下载链接可访问(至少抽查一个平台)
- [ ] 校验和验证通过:

```bash
gh release download vX.Y.Z -R kpge/secCompileOption \
  -p "scc-vX.Y.Z-linux-amd64" -p "checksums.txt"
sha256sum -c <(grep linux-amd64 checksums.txt)
```

- [ ] 下载的二进制可执行且输出版本:

```bash
chmod +x scc-vX.Y.Z-linux-amd64
./scc-vX.Y.Z-linux-amd64 version   # 应输出 secCompileCheck (scc) vX.Y.Z
./scc-vX.Y.Z-linux-amd64 file /bin/ls
```

- [ ] release notes 中的下载示例 URL 与实际资产名一致
- [ ] tag 指向的 commit 与发布时 `main` 顶部一致
- [ ] (双平台)GitCode tag 与 GitHub tag 指向同一 commit
- [ ] (双平台)GitCode Release 同名资产的校验和与 GitHub 一致(§6.6 完成后)

### 6.6 同步 GitCode tag、Release 与正式制品

GitHub workflow 全部成功后,将同一 tag 与同一批正式制品同步到 GitCode。**禁止在 GitCode 侧重新构建另一套制品**——同步的是 GitHub Release 已验证的资产。

前置:已安装 gitcode cli(`gc`,https://gitcode.com/gitcode-cli/cli)并 `gc auth login` 登录;本地 `origin` 指向 GitCode 仓库。

```bash
# 1. 确认双端 tag 一致(同一 commit)
git fetch origin --tags
git ls-remote --tags origin | grep vX.Y.Z
git ls-remote --tags github | grep vX.Y.Z

# 2. 下载 GitHub Release 的正式制品并验证校验和
gh release download vX.Y.Z -R kpge/secCompileOption --dir dist/github-release
cd dist/github-release
sha256sum -c checksums.txt
cd ../..

# 3. 用同一份 release notes 创建 GitCode Release 并上传同一批制品
gh release view vX.Y.Z -R kpge/secCompileOption --json body -q .body > dist/notes-vX.Y.Z.md
gc release create vX.Y.Z -R SmartCICD/secCompileOption   --title "secCompileCheck vX.Y.Z" --notes-file dist/notes-vX.Y.Z.md --target main
gc release upload vX.Y.Z dist/github-release/* -R SmartCICD/secCompileOption
```

注意:

- 上传 GitCode 前必须先通过完整校验和验证
- GitCode Release 会自动附带源码包(.zip/.tar.gz 等),无需手工上传
- 不把 `gh` 或 `gc` 保存的 token 提取出来交给脚本或 curl;认证由 CLI 自身封装
- 网络中断会导致下载产物损坏(表现为校验和不符),重新下载该文件即可,不要跳过校验

### 6.7 备用触发方式:直接推 tag

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

tag 推送同样触发 release.yml,但**没有** `Validate version` 预检(格式校验隐含在构建产物的版本注入中,tag 冲突由 `--verify-tag` 兜底)。适用于:

- 无法使用 gh CLI / 网页的场景
- 重跑一个已存在 tag 的发布(此时代码路径走"幂等跳过或拒绝差异")

日常发布一律走 §6.3 的手动触发。

## 7. Release Notes 规则

当前 release notes 由 `Publish` job 自动生成(功能简介 + 安装命令),版本号取自 tag,杜绝手写版本号不一致。

若未来改为手写 notes(`docs/releases/vX.Y.Z.md`),必须满足:

- 描述本次更新内容,明确修复的 issue 或变更的检测项
- 提供完整安装方式,下载链接必须是完整路径
- 版本号必须与实际产物一致

不允许:

- 只写文件名,不写完整下载地址
- 使用与实际版本不一致的安装命令
- 在未验证产物存在前写入下载示例

## 8. 文档同步要求

发布流程、版本策略或安装方式变化时,必须同步检查:

- `RELEASE.md`(本文件)
- `README.md`(安装章节的版本示例)
- `.github/workflows/release.yml`(实际行为)
- `THIRD_PARTY_LICENSES.md`(仅当检测能力变更涉及新的上游参考时)

## 9. 禁止事项

以下行为不允许:

- 未验证产物即创建正式 release(workflow 已通过校验和强制;人工不得绕过 workflow 直接 `gh release create`)
- 在 workflow 之外手工上传/替换 release 资产
- 移动或删除已对外发布的 tag
- 版本号回退或重用
- 用个人临时脚本替代仓库标准流程而不更新文档
- 把 workflow 中注入的 `GITHUB_TOKEN` 提取出来交给脚本或 curl

## 10. 当前执行基线

当前发布执行基线为:

1. 本地 `go vet` / `go test` / 构建验证通过
2. `main` 最新 CI 全绿
3. 人工通过 workflow_dispatch 触发 `release.yml`,填入规范版本号
4. workflow 从当前 `main` commit 出 tag、构建 6 平台产物、校验 SHA-256、创建 GitHub Release
5. 发布人按 §6.6 将同一 tag 与同一批制品同步到 GitCode Release(不重新构建)
6. 发布人按 §6.5 清单完成发布后验证(含双平台一致性)
