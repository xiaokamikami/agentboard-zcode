# agentboard-zcode

让 [AgentBoard](https://agentboard.cc) 的 Codex 统计合并上报本机 [ZCode](https://zcode.ai) 的 token 用量。

AgentBoard 官方采集器目前不支持 ZCode（`collect_zcode.py` 在服务端返回 404）。本仓库在官方 `collect_codex.py` 的基础上做了最小侵入修改：**ZCode 用量以 `source=opencode` 上传**，会话 ID 为 `opencode:zcode:<session_id>`——这样 ZCode 的消耗在排行榜上单独显示在 OpenCode 名下，不会和真实 Codex 的用量混在一起，方便区分。

## 工作原理

- 读取本机 ZCode SQLite 数据库（默认 `~/.zcode/cli/db/db.sqlite`），只读模式打开，不写入。
- token 数据源为 `model_usage` 表中 `status='completed'` 的请求（`turn_usage` 会严重漏计，约为真实用量的 1/8）。
- ZCode 的 `input_tokens` 已包含缓存 token，而上报后 AgentBoard 展示总量 = tokens_used + cache_read + cache_creation，因此上传前扣除缓存部分，避免缓存被双倍统计。
- error/cancelled 请求也计入活跃时间窗口（限流重试等待是真实的工作时间），但不产生 token。
- 活跃窗口算法与官方 `build_engaged_windows` 语义严格一致（10 分钟断档切分、段尾补 gap、单会话 480 分钟 / 单日 960 分钟上限），已通过随机事件序列等价测试。
- 增量同步：每个 (session, date) 的聚合内容做哈希，存于 `~/.agentboard/zcode-sync-state.<hostname>.json`；无变化不重复上传，依赖服务端 (session_id, user, date) 幂等 upsert。
- 消息/工具只上传数量和工具名计数，不上传 prompt、回复、代码或路径内容。

### 静默运行设计（内存与开销不随历史增长）

- **签名快速路径**：每次同步先对 DB 做一次纯 SQL 聚合签名（行数/最大时间戳/token 总和）。签名没变（ZCode 空闲时）直接跳过整个采集流程，只有几毫秒开销。
- **滑动窗口**：默认只采集最近 45 天（`AGENTBOARD_ZCODE_DAYS` 可调，最小 1）。更早的数据早已上传到服务端，不会再读、不会进 state，扫描时间和内存都是有界的。
- **合并区间代替事件点**：每天的活动时间用"合并后的区间列表"（每段一条）维护，而不是逐事件点，内存 O(活跃段数) 而非 O(事件数)，重度使用一整天也只有几十个区间。
- 守护进程（launchd 每 5 分钟）实际运行内存约 **34MB** 峰值；`--summary`（全量诊断用）约为其 9 倍属正常。

## 安装

前提：本机已按官方脚本安装 AgentBoard CLI（存在 `~/.agentboard/config.json` 和 launchd 定时任务 `cc.agentboard.codex-sync`）。

1. 备份原文件：

   ```bash
   cp ~/.agentboard/collect_codex.py ~/.agentboard/collect_codex.py.bak
   ```

2. 用本仓库的 `collect_codex.py` 覆盖 `~/.agentboard/collect_codex.py`（scp 或直接下载均可）。

3. 本地验证（不上传）：

   ```bash
   python3 ~/.agentboard/collect_codex.py --summary
   ```

   输出中会同时包含真实 Codex 与 `opencode:zcode:` 前缀的 ZCode 会话。

4. 手动同步一次并观察日志：

   ```bash
   python3 ~/.agentboard/collect_codex.py --sync --json
   ```

   首次会全量重发 ZCode 历史；再跑一次应只增量同步活跃会话。

5. launchd 定时任务无需改动（仍是每 5 分钟跑 `--sync`），新采集器会在同一个锁内先同步 Codex 再同步 ZCode。

### 可配置项

- `AGENTBOARD_ZCODE_DB`：ZCode 数据库路径覆盖（默认 `~/.zcode/cli/db/db.sqlite`），测试或多实例时使用。
- `AGENTBOARD_ZCODE_DAYS`：滑动窗口天数（默认 45），设得越大回溯的历史越多。改大之后下次同步会把窗口内新纳入的天自动补传（幂等）。

### 回滚

恢复备份文件即可；ZCode 增量状态文件 `~/.agentboard/zcode-sync-state.*.json` 可一并删除（删除后下次全量重发）。

## 注意事项

- 网站上的数据是**同一账号下所有设备**的合计；单机验证请以本地 `--summary` 为准。
- 网站"今天"卡片约滞后一天聚合，日趋势图才是当天实时值。
- 单位换算：1 亿 = 100M = 0.1B，1B = 10 亿。
- 修改会话语义（如统计口径变化）时需递增脚本内 `ZCODE_SYNC_STATE_VERSION`，强制一次全量重发让服务端覆盖旧数据。

## 许可

仅供个人使用，随官方脚本行为演进，无兼容性承诺。
