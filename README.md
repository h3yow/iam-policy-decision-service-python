# IAM Policy Decision Service（本地策略即代码授权决策）

用本地 JSON 策略文件模拟云上身份与资源的权限规则，提供可解释、可复现的
授权判定。基于 FastAPI，全部依赖为 `fastapi[standard]` 与 `pytest`（开发依赖）。

## 策略表达范围

策略包是一个 JSON 对象：

```json
{
  "version": "v1",
  "subjects":  {"alice": ["employee"], "employee": ["user"]},
  "resources": {"doc-1": ["folder-a"]},
  "rules": [
    {"id": "allow-employee-read", "effect": "allow", "priority": 10,
     "subjects": ["employee"], "actions": ["read"], "resources": ["folder-a"],
     "condition": {"env": "prod"}}
  ]
}
```

- `version`：非空字符串，全局唯一，重复加载会被拒绝。
- `subjects` / `resources`：继承关系，`子节点 -> [父节点]`，求值时沿链向上
  展开（alice 继承 employee 的权限）。继承环在加载期即被拒绝。
- `rules[]`：
  - `id`（必填，唯一）、`effect`（`allow`/`deny`）、`priority`（整数，越大越优先）；
  - `subjects` / `actions` / `resources`：字符串列表，缺省或为空表示通配；
  - `condition`：键值对，请求上下文必须包含且相等才命中；**属性缺失即
    不匹配，不会默认放行**。

## 优先级与冲突处理

1. 主体/资源沿继承链展开后逐条匹配规则，**所有命中的规则都会记录在
   判定结果的 `matched_rules` 中**，不跳过、不静默取舍。
2. 最终结论取**最高优先级**的命中规则；同一最高优先级内同时存在
   `allow` 与 `deny` 时，**deny 优先**（安全方向，结论确定）。
3. 匹配面完全相同、优先级相同但结论相反的规则属于**矛盾规则**，
   在加载校验期直接拒绝，不会进入运行期。
4. 无任何规则命中时**默认拒绝**，并在 `reason` 中说明。
5. 同一请求重复或并发求值，结论与命中规则列表完全一致。

## 版本加载与切换

- `POST /policies`：加载并完整校验新版本。校验失败不影响当前生效版本，
  拒绝原因可区分：
  - `syntax`（HTTP 422）：JSON 非法、字段类型/必填项错误；
  - `semantic`（HTTP 422）：继承环、规则 ID 重复、矛盾规则；
  - `duplicate_version`（HTTP 409）：版本号已存在。
- `POST /policies/{version}/activate`：原子切换到已登记版本；切回旧版本
  即回滚。切换不存在的版本返回 400 且状态不变。
- `GET /policies`：查看已登记版本与当前生效版本。
- `POST /decide`：判定请求 `{"subject","action","resource","context"}`，
  返回 `outcome`、`policy_version`、`reason` 与全部 `matched_rules`
  （含继承路径），服务端日志同步打印请求输入与判定依据。

## 本地验证

```bash
# 安装依赖
uv sync

# 运行全部测试（含并发切换/回滚、畸形策略、继承冲突用例，
# 日志中可见每个请求的输入与判定依据）
uv run pytest -v

# 启动服务
uv run uvicorn main:app --port 8000

# 加载示例策略并切换版本
curl -X POST localhost:8000/policies -H 'content-type: application/json' -d @policies/v1.json
curl -X POST localhost:8000/policies/v1/activate
curl -X POST localhost:8000/decide -H 'content-type: application/json' \
     -d '{"subject":"alice","action":"read","resource":"doc-1"}'

# 加载 v2（allow 优先级高于 deny），切换后同一请求结论翻转为 allow；
# 再 activate v1 即完成回滚
curl -X POST localhost:8000/policies -H 'content-type: application/json' -d @policies/v2.json
curl -X POST localhost:8000/policies/v2/activate
curl -X POST localhost:8000/policies/v1/activate
```

## 代码结构

- `policy_service/models.py`：策略与决策的不可变数据模型；
- `policy_service/errors.py`：可区分的拒绝原因（语法/语义/版本重复）；
- `policy_service/loader.py`：解析与完整校验（先语法后语义）；
- `policy_service/engine.py`：继承求值与确定性冲突处理；
- `policy_service/store.py`：线程安全的版本仓库，原子切换与回滚；
- `main.py`：HTTP 接口；
- `tests/`：加载器、引擎、API 与并发测试。
