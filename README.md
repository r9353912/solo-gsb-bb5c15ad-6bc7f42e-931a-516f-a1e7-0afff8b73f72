# 公开档案敏感片段遮盖 API

基于 Python + FastAPI 的无状态服务：提交一段原文和若干候选敏感片段，服务在
**互不重叠**的前提下选出最优片段组合，并用等长的 `█`（U+2588 FULL BLOCK）
遮盖原文。片段之间允许重叠（提交时无需预处理），相邻片段可同时入选。
另提供 `POST /redact/revise`：先按码点区间编辑修订原文，自动作废旧片段、
迁移保留片段，再完成选择与遮盖；`POST /redact/budget`：在给定的
遮盖码点总预算内选择最优组合；以及 `POST /redact/publish`：按与
`POST /redact` 相同的校验与选段规则发布**脱敏凭证**，仅持久化遮盖正文、
入选区间与带随机盐的原文 SHA-256 摘要（**不保存原文**），凭证串成
SHA-256 哈希链，客户端留存链值后可随时经
`GET /redact/publish/{id}/verify` 核验档案是否被改动。
还可经 `GET /redact/publish/{id}/export` 在单次 SQLite 读事务中导出
第 1 至第 `id` 条的**便携核验包**（只含脱敏数据，不含原文），再用
`POST /redact/publish/verify-package` 提交该包与客户端另存的末端链值，
**不访问数据库**逐条重算哈希链做离线核验。

## 一条命令启动

需要 Docker（含 Compose 插件，Docker Desktop 自带），**无需任何外部账号或密钥**：

```bash
docker compose up --build
```

服务地址与端口：

- API 地址：`http://localhost:8000`
- 健康检查：`GET http://localhost:8000/health`
- 交互文档（Swagger UI）：`http://localhost:8000/docs`
- OpenAPI 描述：`http://localhost:8000/openapi.json`

后台运行可加 `-d`，停止使用 `docker compose down`。

访问端口固定为宿主机 **8000**（`http://localhost:8000`）。
脱敏凭证写入 SQLite 数据库并保存在 Docker **命名卷 `redaction-data`**
（容器内 `/data/redaction.db`）中：`docker compose down`、重建镜像、
重启容器都不会丢失凭证链；仅当显式删除卷
（`docker compose down -v`）时才会清空。

> **凭证留存（重要）**：每次发布返回的 `chain_value` 是该凭证的哈希链值，
> 服务端不会替你另行备份。请在发布成功后**立即由客户端自行保存**
> `credential_id` 与 `chain_value`（例如写入自己的台账），日后核验时
> 原样传回即可。无需保存原文——服务端本来就不保存原文，只保存加盐摘要。
> 需要离线核验或向第三方出示时，可再经
> `GET /redact/publish/{id}/export` 导出便携核验包，连同留存的末端
> 链值交给 `POST /redact/publish/verify-package` 核验。

## API

### `POST /redact`

请求体（`Content-Type: application/json`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `text` | string | 待处理原文 |
| `fragments` | array | 候选片段列表，允许重叠 |
| `fragments[].id` | integer 或 string | 片段唯一 ID；一次请求内所有 ID 必须同为整数或同为字符串 |
| `fragments[].weight` | integer | 权重，**正整数**（`>= 1`） |
| `fragments[].start` | integer | 起始位置，**左闭**，按 Unicode 码点计数，从 0 开始 |
| `fragments[].end` | integer | 结束位置，**右开**；区间为 `[start, end)` |

返回体：

| 字段 | 说明 |
| --- | --- |
| `selected_ids` | 入选片段 ID，按升序排列 |
| `rejected_ids` | 落选片段 ID，按升序排列 |
| `masked_text` | 入选片段覆盖的每个码点替换为一个 `█` 后的正文（长度与原文一致） |

#### 选择目标（按优先级）

1. **权重总和最大**；
2. 权重总和并列时，**遮盖字符数（区间长度之和）最多**；
3. 仍并列时，取**入选 ID 升序列表字典序最小**的组合
   （Python 序列字典序：逐位比较，前缀较短者更小）。

相邻区间（如 `[0,3)` 与 `[3,5)`）不重叠，可以同时入选。
算法为带权区间调度动态规划，时间复杂度 O(n log n)。

#### 示例

```bash
curl -s http://localhost:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "你好，世界！",
    "fragments": [
      {"id": 1, "weight": 5, "start": 0, "end": 3},
      {"id": 2, "weight": 3, "start": 0, "end": 2},
      {"id": 3, "weight": 1, "start": 2, "end": 5}
    ]
  }'
```

响应：

```json
{
  "selected_ids": [1],
  "rejected_ids": [2, 3],
  "masked_text": "███世界！"
}
```

片段 1 与片段 2、3 都重叠；片段 2+3 虽能相邻组合且遮盖字符更多，但权重总和
4 < 5，因此入选片段 1。

相邻片段同时入选的例子：

```bash
curl -s http://localhost:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "abcdef",
    "fragments": [
      {"id": 1, "weight": 1, "start": 0, "end": 3},
      {"id": 2, "weight": 1, "start": 3, "end": 6}
    ]
  }'
# {"selected_ids":[1,2],"rejected_ids":[],"masked_text":"██████"}
```

#### 校验规则（不合法请求返回 HTTP 400）

以下情况一律拒绝，响应形如 `{"detail": "中文错误说明"}`：

- 缺少 `text` / `fragments`，或片段缺少 `id` / `weight` / `start` / `end`；
- 类型错误：如权重或位置不是整数（不接受 `1.0`、`true`、`"1"`），ID
  不是整数或字符串；
- 权重不是正整数（`<= 0`）；
- 区间越界（`start < 0` 或 `end > 原文码点长度`）；
- 空片段或反向区间（`start >= end`）；
- 重复 ID；
- 整数 ID 与字符串 ID 混用；
- 请求体不是合法 JSON。

### `POST /redact/budget`

与 `POST /redact` 使用相同的 `text`、`fragments` 校验与等长 `█` 遮盖规则，
另接收非负整数 `max_masked_chars`（遮盖码点总预算）。只在**互不重叠且
遮盖码点总数不超过预算**的组合中，按与 `POST /redact` 相同的优先级
（权重总和 → 遮盖码点数 → 入选 ID 升序列表字典序）选出结果，相邻区间
仍可同时入选。返回结果额外包含实际遮盖码点数 `used_chars`。

请求体（`Content-Type: application/json`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `text` | string | 待处理原文（同 `POST /redact`） |
| `fragments` | array | 候选片段列表，允许重叠（同 `POST /redact`） |
| `max_masked_chars` | integer | 遮盖码点总预算，**非负整数**；为 `0` 时不遮盖任何码点，直接返回原文 |

返回体：

| 字段 | 说明 |
| --- | --- |
| `selected_ids` | 入选片段 ID，按升序排列 |
| `rejected_ids` | 落选片段 ID，按升序排列 |
| `masked_text` | 入选片段覆盖的每个码点替换为一个 `█` 后的正文（长度与原文一致） |
| `used_chars` | 入选片段实际遮盖的码点总数（区间长度之和，`<= max_masked_chars`） |

#### 示例

```bash
curl -s http://localhost:8000/redact/budget \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "abcdef",
    "fragments": [
      {"id": 1, "weight": 5, "start": 0, "end": 4},
      {"id": 2, "weight": 3, "start": 0, "end": 2}
    ],
    "max_masked_chars": 3
  }'
```

响应：

```json
{
  "selected_ids": [2],
  "rejected_ids": [1],
  "masked_text": "██cdef",
  "used_chars": 2
}
```

片段 1（`[0,4)`）需遮盖 4 个码点，超出预算 3，即使权重更高也不能入选；
片段 2（`[0,2)`）只需 2 个码点，在预算内取得最高权重总和。

预算为零时返回未遮盖原文：

```bash
curl -s http://localhost:8000/redact/budget \
  -H 'Content-Type: application/json' \
  -d '{"text": "你好，世界！", "fragments": [
    {"id": 1, "weight": 5, "start": 0, "end": 3}
  ], "max_masked_chars": 0}'
# {"selected_ids":[],"rejected_ids":[1],"masked_text":"你好，世界！","used_chars":0}
```

#### 校验规则（不合法请求返回 HTTP 400）

- `max_masked_chars` 缺失，或不是非负整数
  （不接受 `-1`、`1.0`、`true`、`"3"`、`null`；注意布尔值是整数子类也被拒绝）；
- `text` / `fragments` 的校验规则与 `POST /redact` 完全一致；
- 请求体不是合法 JSON。

### `POST /redact/revise`

先把一批编辑一次性应用到原文，再对**未被编辑波及**的片段做最优选择与遮盖。
片段与编辑区间均按**修订前原文**的 Unicode 码点定位。

请求体（`Content-Type: application/json`）：`text` 与 `fragments` 字段同
`POST /redact`，另需 `edits` 数组：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `edits` | array | 编辑列表，按原文码点定位，一次性应用 |
| `edits[].start` | integer | 编辑起始位置，**左闭**，`>= 0` |
| `edits[].end` | integer | 编辑结束位置，**右开**；`start == end` 表示纯插入 |
| `edits[].replacement` | string | 替换文本；空字符串表示删除 `[start, end)` |

返回体：

| 字段 | 说明 |
| --- | --- |
| `revised_text` | 应用全部编辑后的原文 |
| `invalidated_ids` | 被编辑波及而作废的片段 ID，按升序排列 |
| `selected_ids` | 保留片段中入选的 ID，按升序排列 |
| `rejected_ids` | 保留片段中落选的 ID，按升序排列（**不含**作废 ID） |
| `masked_text` | 修订后正文中入选片段以等长 `█` 遮盖的结果（长度与 `revised_text` 一致） |

#### 片段作废与迁移规则

对每个旧片段：

- 删除/替换区间与片段**有交集**，或插入点**严格落在片段内部**
  （`start < p < end`）：片段**作废**，进入 `invalidated_ids`；
- 插入在片段**起点**：整段右移，插入内容不并入片段；
- 插入在片段**终点**：不扩展片段，区间不变；
- 其余保留片段长度不变，按前方编辑的**累计码点位移**整体平移区间，
  再参与与 `POST /redact` 相同的最优选择与遮盖。

#### 编辑校验规则（不合法请求返回 HTTP 400）

- 缺少 `edits`，或编辑缺少 `start` / `end` / `replacement`；
- 类型错误：位置不是整数（不接受 `1.0`、`true`），`replacement` 不是字符串；
- 区间越界（`start < 0` 或 `end > 原文码点长度`）或逆序（`start > end`）；
- 编辑区间彼此重叠（相邻，即前一区间 `end ==` 后一区间 `start`，不算重叠）；
- 同一位置的多次插入；
- `text` / `fragments` 的校验规则与 `POST /redact` 一致。

#### 示例

```bash
curl -s http://localhost:8000/redact/revise \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "你好，世界！",
    "fragments": [
      {"id": 1, "weight": 5, "start": 0, "end": 2},
      {"id": 2, "weight": 3, "start": 3, "end": 5}
    ],
    "edits": [
      {"start": 2, "end": 3, "replacement": "！"},
      {"start": 6, "end": 6, "replacement": "再见"}
    ]
  }'
```

响应：

```json
{
  "revised_text": "你好！世界！再见",
  "invalidated_ids": [],
  "selected_ids": [1, 2],
  "rejected_ids": [],
  "masked_text": "██！██！再见"
}
```

编辑与两个片段均只是相邻而非相交，插入在文末，因此没有片段作废，两个片段
区间不变、同时入选。

删除与片段相交、其余片段随位移迁移的例子：

```bash
curl -s http://localhost:8000/redact/revise \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "abcdef",
    "fragments": [
      {"id": 1, "weight": 1, "start": 1, "end": 3},
      {"id": 2, "weight": 1, "start": 4, "end": 6}
    ],
    "edits": [
      {"start": 2, "end": 4, "replacement": ""}
    ]
  }'
```

响应：

```json
{
  "revised_text": "abef",
  "invalidated_ids": [1],
  "selected_ids": [2],
  "rejected_ids": [],
  "masked_text": "ab██"
}
```

删除区间 `[2,4)` 与片段 1（`[1,3)`）相交，片段 1 作废；片段 2（`[4,6)`）
在删除之后，整体左移 2 个码点至 `[2,4)`，遮盖修订后文本中的 `"ef"`。

### `POST /redact/publish`

按与 `POST /redact` **完全相同**的 `text`、`fragments` 校验与选段规则
完成选择与遮盖，并把结果作为**脱敏发布凭证**持久化。请求体与
`POST /redact` 相同（仅需 `text` 与 `fragments`），校验失败同样返回 HTTP 400。

凭证**只持久化**以下内容，原文不入库：

| 持久化内容 | 说明 |
| --- | --- |
| 遮盖正文 `masked_text` | 入选片段等长 `█` 遮盖后的正文 |
| 入选区间 `ranges` | 入选片段的 `[start, end)` 码点区间，按起点升序 |
| 原文摘要 `text_digest` | `"<随机盐 hex>$<sha256(盐 || 原文 UTF-8) hex>"`；随机盐（32 字节）保证相同原文摘要也不重复，无法据此反查常见原文 |
| 凭证编号 `seq` | 从 1 开始连续递增 |
| 链值 `chain_value` | 见下文哈希链规则 |

返回体：

| 字段 | 说明 |
| --- | --- |
| `credential_id` | 凭证编号（从 1 开始连续递增） |
| `selected_ids` | 入选片段 ID，按升序排列 |
| `masked_text` | 遮盖正文（与 `POST /redact` 的结果一致） |
| `chain_value` | 本凭证链值，64 位十六进制 SHA-256；**客户端需自行留存** |

哈希链规则：第一条凭证的前一链值为 64 个 `0`（创世链值）；每条新凭证的
链值为对“规范化凭证内容 + 前一链值”取 SHA-256。规范化内容为固定字段集合
（编号、遮盖正文、入选区间、原文摘要、前一链值）的紧凑 UTF-8 JSON
（键排序、无空白、非 ASCII 直出），任何实现都能重算出同一结果。

编号分配与链值写入在单条 SQLite 事务（`BEGIN IMMEDIATE` 立即写锁，
配合 30 秒忙等待）中完成，并发请求严格串行排队，编号连续、链顺序一致。

#### 示例

```bash
curl -s http://localhost:8000/redact/publish \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "你好，世界！",
    "fragments": [
      {"id": 1, "weight": 5, "start": 0, "end": 3},
      {"id": 2, "weight": 3, "start": 0, "end": 2}
    ]
  }'
```

响应（`chain_value` 因随机盐每次不同）：

```json
{
  "credential_id": 1,
  "selected_ids": [1],
  "masked_text": "███世界！",
  "chain_value": "d47320fae8f27cbfea41b6528c6215e790d5fe6b26f9d5e3bb949ff63a778b8a"
}
```

### `GET /redact/publish/{id}/verify`

凭客户端发布时留存的链值，重算从第 1 条到第 `id` 条的全部凭证记录，
核验哈希链是否完整、尾链值是否与留存值一致。

查询参数：

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `chain_value` | string | **必填**，发布时留存的该凭证链值（64 位小写十六进制）；缺失或格式错误返回 HTTP 400 |

路径参数 `id` 不存在时返回 HTTP 404。

返回体（HTTP 200）：

| 字段 | 说明 |
| --- | --- |
| `credential_id` | 被核验的凭证编号 |
| `valid` | 链完整（无断裂）且服务端重算链值等于客户端留存链值时为 `true` |
| `first_broken_id` | 首个断裂编号（记录缺失/不连续，或该记录重算链值与库存不符）；无断裂为 `null` |
| `chain_value_matches` | 服务端链值是否与客户端留存链值一致 |
| `server_chain_value` | 服务端截至该凭证的链值；链断裂时为当前库存尾链值，便于排查 |

示例：

```bash
curl -s 'http://localhost:8000/redact/publish/1/verify?chain_value=d47320fae8f27cbfea41b6528c6215e790d5fe6b26f9d5e3bb949ff63a778b8a'
# {"credential_id":1,"valid":true,"first_broken_id":null,
#  "chain_value_matches":true,"server_chain_value":"d473...778b8a"}
```

注意两种不同的“不通过”：

- 留存链值写错、但服务端档案本身完整：`valid=false`、
  `first_broken_id=null`、`chain_value_matches=false`；
- 服务端档案被改动或缺失：`valid=false`，`first_broken_id` 指向
  **首个**出问题的编号；断裂点之前的旧凭证仍可单独核验通过。

### `GET /redact/publish/{id}/export`

导出**便携核验包**：在一次 SQLite 读事务（WAL 快照，不阻塞并发发布）中
取出第 1 条到第 `id` 条的全部凭证，按编号升序返回。包内只有脱敏数据——
编号、遮盖正文、入选区间、带盐原文摘要与链值，**不含原文**；
`id` 不存在时返回 HTTP 404。

返回体（HTTP 200）：

| 字段 | 说明 |
| --- | --- |
| `through_seq` | 导出截止的凭证编号（即路径中的 `id`） |
| `records` | 第 1 至第 `id` 条凭证记录，按编号升序 |
| `records[].seq` | 凭证编号 |
| `records[].masked_text` | 遮盖正文 |
| `records[].ranges` | 入选码点区间 `[[start, end], ...]`，按起点升序 |
| `records[].text_digest` | 带盐原文摘要 `"<盐 hex>$<摘要 hex>"` |
| `records[].chain_value` | 该凭证链值（64 位十六进制 SHA-256） |

#### 示例

```bash
curl -s http://localhost:8000/redact/publish/2/export
```

响应（摘要与链值因随机盐每次不同）：

```json
{
  "through_seq": 2,
  "records": [
    {
      "seq": 1,
      "masked_text": "███世界！",
      "ranges": [[0, 3]],
      "text_digest": "15a5ec…（64 位盐 hex）$4e8ad3…（64 位摘要 hex）",
      "chain_value": "f991122b2e18a9c20d9501246f6c7a81cc41c94f86529fc601824aaece343ff4"
    },
    {
      "seq": 2,
      "masked_text": "██████",
      "ranges": [[0, 3], [3, 6]],
      "text_digest": "021454…$bf9ab5…",
      "chain_value": "f329f13aefe0185000cd1d61432d7729db739fe5cb31d783c7e252fd82b60dd3"
    }
  ]
}
```

### `POST /redact/publish/verify-package`

**离线核验**便携核验包：**不访问数据库**，按与发布时相同的规范从创世链值
（64 个 `0`）起对包内记录逐条重算哈希链并逐一比对；链完整时再把第
`through_seq` 条的链值与客户端**另存的末端链值**做恒定时间比较。
适合把导出的包交给第三方独立核验，或服务端不可用时本地核验。

请求体（`Content-Type: application/json`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `package` | object | `GET /redact/publish/{id}/export` 返回的完整对象（含 `through_seq` 与 `records`） |
| `tail_chain_value` | string | 客户端另存的末端链值，即发布第 `through_seq` 条时返回的 `chain_value`（64 位小写十六进制） |

返回体（HTTP 200）：

| 字段 | 说明 |
| --- | --- |
| `through_seq` | 核验包声明的截止编号 |
| `valid` | 链完整（无缺号、无篡改）**且**末端链值相符时为 `true` |
| `first_broken_id` | 首个断裂编号：缺号（含尾部缺记录）为第一个缺失编号，内容或链值被改为该条编号；无断裂为 `null` |
| `tail_chain_value_matches` | 重算末端链值与客户端留存值是否一致（链断裂时恒为 `false`） |

格式错误一律返回 HTTP 400：请求体不是合法 JSON、缺少 `package` /
`tail_chain_value` 或记录字段、类型错误（不接受布尔/浮点/字符串形式的
编号与位置）、`tail_chain_value` 或记录 `chain_value` 不是 64 位小写
十六进制、`records` 为空或条数超过 `through_seq` 等。

#### 示例

```bash
# 导出核验包并保存到本地文件
curl -s http://localhost:8000/redact/publish/2/export > package.json

# 用发布第 2 条时留存的 chain_value 离线核验（jq 仅用于拼装请求体）
curl -s http://localhost:8000/redact/publish/verify-package \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --argjson pkg "$(cat package.json)" \
       --arg tail "f329f13aefe0185000cd1d61432d7729db739fe5cb31d783c7e252fd82b60dd3" \
       '{package: $pkg, tail_chain_value: $tail}')"
```

响应：

```json
{
  "through_seq": 2,
  "valid": true,
  "first_broken_id": null,
  "tail_chain_value_matches": true
}
```

与 `GET /redact/publish/{id}/verify` 的区别：`verify` 核验的是**服务端
当前库存**的链；`verify-package` 核验的是**客户端手中导出的包**，
服务端数据库完全不参与。包被改动时的表现与库存核验一致：缺号或内容、
链值被改都会得到 `valid=false` 与首个断裂编号；只有链完整且末端链值
与留存值相符才是 `valid=true`。

## 码点计数说明

位置与遮盖均以 **Unicode 码点**为单位（即 Python 3 中 `str` 的索引与
`len()`），不是字节，也不是用户感知字符（grapheme cluster）。例如
`"a😀b"` 长度为 3，遮盖 emoji `[1,2)` 得到 `"a█b"`。

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

uvicorn app.main:app --reload --port 8000   # 启动开发服务器
pytest -q                                    # 运行测试
```

测试包含核心算法（选择、预算选择、遮盖、编辑应用、片段迁移）单元测试、
脱敏发布凭证（加盐摘要、哈希链重算、篡改检出、SQLite 并发编号一致性）
单元测试、便携核验包导出与离线核验（缺号、篡改、末端链值不符、格式错误）
端到端测试，以及各 API 端点的端到端测试，另含各 300 组随机用例下
动态规划结果与 2^n 暴力枚举（含带预算版本）的对照校验。

本地运行时凭证数据库默认在工作目录的 `data/redaction.db`，
可用环境变量 `REDACTION_DB_PATH` 覆盖（容器内固定为 `/data/redaction.db`，
由命名卷持久化）。

## 项目结构

```
.
├── app/
│   ├── main.py          # FastAPI 路由、请求校验
│   ├── redaction.py     # 区间调度 DP 与遮盖算法（与框架解耦）
│   └── publishing.py    # 脱敏凭证 SQLite 持久化与 SHA-256 哈希链
├── tests/               # pytest 测试
├── data/                # 本地运行默认的 SQLite 目录（容器内为 /data 卷）
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── requirements-dev.txt
```
