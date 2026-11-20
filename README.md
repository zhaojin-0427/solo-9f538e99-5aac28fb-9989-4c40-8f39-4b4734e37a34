# 空运危险品保管链 API

面向断网后乱序补传场景的保管链（chain of custody）服务。数据员可以据此判断：
在某个时刻之前，哪些交接仍然可信、断链发生在哪里、当前可确认的保管方是谁。

技术栈：**FastAPI + SQLite（WAL 模式）+ Uvicorn**，可通过 `docker compose` 一键启动。

## 核心规则

1. **固定起始保管方**：创建运单时登记 `origin_party`，初始可确认保管方即该方。
2. **批量提交**：每笔扫描携带 `scan_id`、正整数 `revision`、UTC 时刻 `ts_utc`、
   交出方 `giver`、接收方 `receiver`。时刻必须带时区偏移（如 `...Z`、`+08:00`），统一归一化为 UTC 存储。
3. **撤回**：只提交 `scan_id` 与更高的 `revision`，`event_type=WITHDRAWAL`，
   不得携带时刻或当事方；撤回只能针对已存在的扫描 ID。
4. **修订裁决**：
   - 同一 `scan_id` 仅采用**最高修订号**的版本；更低修订号提交返回 `409 stale`。
   - 同修订号、异文（时刻/交出方/接收方/类型不同）**整批拒绝**（`409`），已提交数据原样保留。
   - 同修订号、同文重复提交幂等，不计入写入数。
5. **链核对**（按 UTC 时刻升序，乱序补传自动归位）：
   - 交接的 `giver` 必须等于当前保管方（首笔对照起始保管方，其后对照上一笔的 `receiver`），
     不匹配即为 **GAP 断链**。
   - **同一时刻存在多笔交接时不猜测顺序**：该时刻整组标记为 **SIMULTANEOUS** 断链，组内全部未证实。
   - 断链之后的所有扫描一律 `verified=false`，直到补报、更正或撤回补齐缺口；
     重算后断链位置可以前移、后移或消失。
6. **原子性与一致性**：
   - 每个批次在单个 `BEGIN IMMEDIATE` 事务内完成，任何冲突整批回滚，**失败保留旧链**。
   - 查询只读已提交快照（WAL），交错的扫描提交与查询永远看不到半写状态或混合修订。
   - 数据持久化在 SQLite 文件中，进程重启后状态不变。

## 启动方式

### Docker Compose（推荐）

```bash
docker compose up --build
# 服务： http://localhost:8000
# 文档： http://localhost:8000/docs
# 控制台：http://localhost:8000/
```

数据库保存在命名卷 `chain-data`（容器内 `/data/chain.db`），容器重启不丢数据。

### 本地运行

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
# 可选：APP_DB_PATH=/custom/path/chain.db
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/waybills` | 创建运单并固定起始保管方 |
| GET | `/api/waybills` | 列出全部运单 |
| POST | `/api/waybills/{waybill_id}/scans/batch` | 批量提交交接 / 更正 / 撤回 |
| GET | `/api/waybills/{waybill_id}/chain` | 查询可信前缀、断链原因、当前保管方 |
| POST | `/api/waybills/{waybill_id}/seals` | 封存当前已提交状态的可信前缀与首处断链时刻 |
| GET | `/api/waybills/{waybill_id}/seals/{seal_id}` | 读取封存元数据与留存摘要 |
| POST | `/api/waybills/{waybill_id}/proofs` | 凭封存号与 UTC 时间窗申请核查证明 |
| POST | `/api/verify` | 凭留存摘要与证明离线验真，不读取原库 |
| GET | `/docs` | Swagger UI，可直接录入、封存、出证与验真 |

## 封存、出证与离线验真

保险方只索取某段时间的核查证据，服务按"封存 → 出证 → 验真"三步给出可离线核验的结论。

### 1. 封存（seal）

`POST /api/waybills/{waybill_id}/seals` 在单个 `BEGIN IMMEDIATE` 事务内对**同一已提交
状态**计算可信前缀，并把该前缀不可变地复制到封存表：之后的补报、更正、撤回或进程重启
都不会改变封存内容，仍可用原封存号出证、沿用原摘要。封存失败不留任何记录。

每条封存交接计算叶子哈希（含运单号、序号、scan_id、修订号、UTC 时刻、交出方、接收方），
叶子再汇总为 Merkle 根与清单哈希（manifest hash）。封存同时记录**首处断链时刻与原因**。

返回体中的 `requested_digests` 是可另行留存的摘要：只取 0、1、3、7、15… 号位置，
n 条封存交接至多签发 `floor(log2(n)) + 1` 条摘要（对数增长）。每条摘要的哈希预映像绑定
封存号、运单号、清单哈希、Merkle 根、叶子总数、对应叶子哈希与断链界限。

### 2. 出证（proof）

`POST /api/waybills/{waybill_id}/proofs` 提交封存号与 UTC 半开时间窗
`[start_utc, end_utc)`——**起点必须严格早于终点，含起点、不含终点**，时刻须带时区偏移。
结论只有三种：

| 条件 | 结论 | 附带内容 |
| --- | --- | --- |
| 窗内存在已证实交接 | `HAS_RECORD` | 窗内全部交接（含序号、时刻、当事方与 Merkle 路径） |
| 窗内无交接，但窗尾晚于首处断链时刻 | `INSUFFICIENT_EVIDENCE` | 断链界限 |
| 其余（窗内无交接且未越过断链） | `EMPTY_WINDOW` | 断链界限、窗外紧邻交接（before/after 邻居）及必要序号与摘要 |

空窗证明的紧邻性由**封存序号连续性**保证：双侧邻居满足 `after.idx = before.idx + 1`，
单侧边界对照封存首尾序号（idx 0 / leaf_count−1），数学上排除窗内被隐藏的交接。
每个窗内条目与邻居都带 Merkle 认证路径，可独立验证其属于封存时的 Merkle 根。
证明整体再做一次 `proof_hash`，覆盖信封内全部字段。

### 3. 验真（verify）

`POST /api/verify` 只需要：运单号、封存号、时间窗、留存摘要与证明信封——**全程不读取
数据库**，即使原库被替换或服务重启也不影响结论。验真会逐项重算：

1. 运单号/封存号/时间窗与证明信封一致；
2. `proof_hash` 覆盖信封全部内容，任何字段改动都会失配；
3. 每条留存摘要哈希（绑定根、叶子总数与断链界限）；
4. 窗内条目与邻居的叶子哈希（时刻、当事方等字段改动即失配）及其 Merkle 路径到根；
5. 窗口半开区间归属、邻居序号连续性，并从零重推三种结论规则。

因此：改动相邻交接的时刻、跳过更靠近窗口的交接、调换运单号或封存号、伪造断链界限、
伪造 Merkle 根或叶子总数，均无法通过验真。**空前缀封存**与**只有一侧边界**的合法
空窗证明同样可以通过验真。

### 端点示例

```bash
# 封存
curl -X POST http://localhost:8000/api/waybills/AWB-001/seals

# 申请证明（半开窗 [09:30, 11:30)）
curl -X POST http://localhost:8000/api/waybills/AWB-001/proofs \
  -H 'Content-Type: application/json' \
  -d '{"seal_id":"<seal_id>","start_utc":"2026-11-18T09:30:00Z","end_utc":"2026-11-18T11:30:00Z"}'

# 离线验真（证明信封中的 requested_digests 即留存摘要）
curl -X POST http://localhost:8000/api/verify -H 'Content-Type: application/json' \
  -d '{"waybill_id":"AWB-001","seal_id":"<seal_id>","start_utc":"...","end_utc":"...",
       "retained_digests":[...],"proof":{...}}'
```

### 交接批次示例

```json
{
  "scans": [
    {"scan_id": "S1", "revision": 1, "ts_utc": "2026-11-18T08:00:00Z",
     "giver": "HKG-WAREHOUSE", "receiver": "CX-CARGO"},
    {"scan_id": "S2", "revision": 1, "ts_utc": "2026-11-18T10:30:00Z",
     "giver": "CX-CARGO", "receiver": "PVG-WAREHOUSE"}
  ]
}
```

### 撤回示例（修订号必须更高）

```json
{"scans": [{"scan_id": "S2", "revision": 2, "event_type": "WITHDRAWAL"}]}
```

### 查询响应示例（发生断链时）

```json
{
  "waybill_id": "AWB-001",
  "origin_party": "HKG-WAREHOUSE",
  "current_custodian": "CX-CARGO",
  "verified_prefix": [ {"scan_id": "S1", "verified": true, "...": "..."} ],
  "unverified_scans": [ {"scan_id": "S3", "verified": false,
                         "unverified_reason": "GAP"} ],
  "chain_intact": false,
  "break_reason": "GAP",
  "break_detail": "giver 'X' does not hold custody; expected 'CX-CARGO' ...",
  "break_scan_ids": ["S3"]
}
```

`break_reason` 取值：`NONE` / `GAP`（保管方不承接）/ `SIMULTANEOUS`（同时刻多笔，顺序不可判定）。
`current_custodian` 只沿已证实交接推进，因此断链后仍可信地停留在最后一个已证实接收方。

## 测试

```bash
pip install pytest httpx
pytest -q
```

共 50 个用例，覆盖：乱序补传归位、时区归一化、最高修订裁决、同修订异文整批回滚、
撤回与补报修复断链、GAP/SIMULTANEOUS 检测、输入校验、真实线程下的写串行化、
交错读不到混合修订、进程重启持久化；以及封存快照与不可变性、摘要对数增长、
三类出证结论与半开区间边界、单侧边界与空前缀封存、离线验真、时刻/当事方/叶子/
Merkle 路径/运单号/封存号/断链界限等各类篡改均被拒绝、封存与提交交错只见已提交状态、
封存跨重启继续出证。
