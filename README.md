# IPv4 遮蔽分析 API

基于 **Python + FastAPI** 的 IPv4 CIDR 规则遮蔽（shadowing）分析服务。

按输入顺序处理一组有序的 `allow` / `deny` CIDR 规则，计算每条规则
**未被此前任何规则覆盖**的地址集合，并分为：

| 状态 | 值 | 含义 |
| --- | --- | --- |
| 全生效 | `full` | 规则地址均未被此前规则覆盖 |
| 部分遮蔽 | `partial` | 部分地址此前已被覆盖 |
| 完全遮蔽 | `shadowed` | 全部地址此前已被覆盖，规则不产生任何生效地址 |

每条规则的生效（剩余）地址集合会**无损压缩成数量最少的 CIDR 列表**，
并在 `summary` 中汇总生效的 `allow`、`deny` 地址数。

> 遮蔽来源不区分动作：先前的 **allow 与 deny 规则取并集**，共同遮蔽后续规则。

---

## 快速开始（Docker Compose 一条命令）

```bash
docker compose up --build -d
```

服务地址与端口：

- **API 基础地址：** http://localhost:8000
- **分析接口：** `POST http://localhost:8000/analyze`
- **交互式文档（Swagger UI）：** http://localhost:8000/docs
- **OpenAPI Schema：** http://localhost:8000/openapi.json
- **健康检查：** http://localhost:8000/health

如需更换宿主机端口（例如改用 18000）：

```bash
HTTP_PORT=18000 docker compose up --build -d
# 随后访问 http://localhost:18000
```

停止服务：

```bash
docker compose down
```

---

## 接口说明

### `POST /analyze`

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/8"},
    {"action": "deny",  "cidr": "10.1.0.0/16"},
    {"action": "allow", "cidr": "192.168.0.0/16"},
    {"action": "deny",  "cidr": "10.0.0.0/7"}
  ]
}
```

- `rules`：**有序**规则列表，按数组顺序逐条处理；至少 1 条。
- `action`：仅允许 `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `cidr`：严格 IPv4 CIDR（如 `10.0.0.0/8`、`0.0.0.0/0`）；
  纯 IP 地址按 `/32` 处理；**主机位必须为零**（如 `10.0.0.1/8` 非法）；
  **禁止 IPv6**。

#### 响应示例（200）

```json
{
  "rule_count": 4,
  "rules": [
    {
      "index": 0,
      "action": "allow",
      "cidr": "10.0.0.0/8",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 16777216,
      "covered_addresses": 0,
      "effective_addresses": 16777216,
      "effective_cidrs": ["10.0.0.0/8"]
    },
    {
      "index": 1,
      "action": "deny",
      "cidr": "10.1.0.0/16",
      "status": "shadowed",
      "status_label": "完全遮蔽",
      "total_addresses": 65536,
      "covered_addresses": 65536,
      "effective_addresses": 0,
      "effective_cidrs": []
    },
    {
      "index": 2,
      "action": "allow",
      "cidr": "192.168.0.0/16",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 65536,
      "covered_addresses": 0,
      "effective_addresses": 65536,
      "effective_cidrs": ["192.168.0.0/16"]
    },
    {
      "index": 3,
      "action": "deny",
      "cidr": "10.0.0.0/7",
      "status": "partial",
      "status_label": "部分遮蔽",
      "total_addresses": 33554432,
      "covered_addresses": 16777216,
      "effective_addresses": 16777216,
      "effective_cidrs": ["11.0.0.0/8"]
    }
  ],
  "summary": {
    "full": 2,
    "partial": 1,
    "shadowed": 1,
    "effective_allow_addresses": 16842752,
    "effective_deny_addresses": 16777216
  }
}
```

`effective_cidrs` 为生效地址集合的最少 CIDR 表示：碎片会先合并
（首尾相邻也合并），再用贪心取最大对齐 2 的幂分块，保证**块数最少且无损**。

#### curl 示例

```bash
curl -s http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"action":"allow","cidr":"0.0.0.0/0"},{"action":"deny","cidr":"8.8.8.8/32"}]}'
```

### 错误响应（422 Unprocessable Entity）

以下输入均返回 HTTP `422`，错误明细位于 `detail`：

- 空规则集：`{"rules": []}` 或缺少 `rules`
- 非法 CIDR：格式错误、前缀越界（`/33`）、主机位非零（`10.0.0.1/8`）等
- IPv6 地址或网段：`2001:db8::/32`、`::1` 等
- 非法 / 缺失 `action`、字段类型错误、JSON 格式错误

---

## 本地开发（不使用 Docker）

需要 Python 3.11+。

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

运行测试：

```bash
pytest -q
```

测试覆盖：解析校验（含 IPv6 拒绝）、区间差集与合并、最少 CIDR 压缩、
三种遮蔽分类、跨动作遮蔽、顺序敏感性，以及用标准库
`ipaddress.collapse_addresses` 作为 oracle 的随机属性测试（无损 + 最少块）。

---

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py    # 核心：CIDR 解析、区间差集、最少 CIDR 压缩、规则分析
│   └── main.py        # FastAPI 应用、请求/响应模型与 /analyze 接口
├── tests/
│   ├── test_analyzer.py
│   └── test_api.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## 设计要点

- **遮蔽语义**：处理第 *i* 条规则时，遮蔽集合 = 前 *i-1* 条规则
  （allow ∪ deny）覆盖地址的并集；规则区间减去遮蔽集合即生效集合。
- **无损压缩**：剩余碎片先合并相邻区间，再以“当前地址能对齐的最大
  2 的幂块、且不越过区间末端”贪心切块，得到最少数量的 CIDR。
- **整数运算**：全部基于 32 位无符号整数区间处理，避免字符串/对象开销，
  可正确支持 `0.0.0.0/0` 全空间等边界场景。
