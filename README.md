# 本地策略即代码授权决策服务（Policy Decision Service）

用本地策略文件（JSON/YAML）模拟云上身份（主体）与资源的权限规则，提供：

- 策略包的**加载校验、版本切换与回滚**：新版本必须完整校验通过才允许生效，失败版本绝不影响当前判定；
- 主体 / 资源的**继承关系求值**：继承环、属性缺失、未知主体/资源一律确定性拒绝，不默认放行；
- 规则冲突的**确定性裁决与可追溯**：命中的每条规则都记录，排序规则固定，结论可复现；
- 并发安全：求值期间任意切换 / 回滚版本，每个结论与其所报版本严格一致；
- 全部判定返回结构化判定依据（命中规则、裁决规则、逐步 trace）。

## 本地启动与验证

```bash
uv sync                          # 安装依赖（fastapi + pyyaml；pytest 为开发依赖）

# 启动服务：自动加载 policies/ 下的示例策略包并激活第一个版本
uv run python main.py            # 默认 127.0.0.1:8000，可用 PORT 覆盖

# 运行全部单测（日志默认打印请求输入与判定依据）
uv run pytest                    # 加 -s 可在测试摘要中看到完整输出
```

### 复现实验（curl）

```bash
# 判定（返回 decision / matched_rules / winning_rule / reason / trace）
curl -s -X POST localhost:8000/decide -H 'Content-Type: application/json' \
  -d '{"subject":"alice","action":"read","resource":"design-doc"}'

# 加载新版本（只校验、不生效）：JSON/YAML 文本放在 text 字段
curl -s -X POST localhost:8000/versions/load -H 'Content-Type: application/json' \
  -d "{\"text\": $(jq -Rs . < policies/v2.json)}"

# 原子切换 / 回滚 / 查看版本
curl -s -X POST localhost:8000/versions/activate -H 'Content-Type: application/json' -d '{"version":"v2-2026-09"}'
curl -s -X POST localhost:8000/versions/rollback
curl -s localhost:8000/versions
```

拒绝原因与 HTTP 状态码的对应：`syntax_error` -> 400，`semantic_error` -> 422，
`duplicate_version` -> 409，响应体中 `message` / `details` 给出可区分的具体原因。

## 策略表达范围

策略包是一个 JSON/YAML 对象，包含 `version`、`subjects`、`resources`、`rules` 四部分，
完整示例见 [`policies/v1.json`](policies/v1.json)。

- **主体 / 资源实体**：`inherits` 声明继承（多继承，允许"是一个"层级），
  `attributes` 携带任意键值属性；子节点属性覆盖父节点同名属性，合并结果在加载时冻结。
- **规则**：`id`（包内唯一）、`effect`（`allow` / `deny`）、`priority`（整数，越大越高）、
  `subjects` / `actions` / `resources`（非空字符串数组，`"*"` 为通配）。
- **属性条件**（可选，全部 AND）：
  - `subject.<attr>` / `resource.<attr>` 指向主体或资源合并后的属性；
  - 操作符：`eq`、`neq`、`in`、`notin`、`exists`（exists 仅检查属性是否存在）。
- 动作（action）只做精确匹配或 `"*"` 通配，无通配模式。

## 判定流程（fail-closed，全程可解释）

1. 主体或资源未在生效策略包中定义 → **deny**；
2. 继承链存在环 → **deny**（加载期同样会拒绝该版本，运行期为防御性兜底）；
3. 计算主体/资源的继承组（自身 + 全部祖先），规则在继承组内匹配，`"*"` 通配；
4. 条件中引用的属性**缺失** → 该规则不命中，且整体 **deny**，原因中列出缺失的属性 key；
   条件不满足 → 该规则不命中；
5. 无任何规则命中 → **deny（默认拒绝）**；
6. 多条规则命中时**全部记录、不跳过**，按确定性排序键取第一条作为裁决规则。

## 优先级与冲突处理规则

命中规则的排序键（依次比较）：

1. `priority` 数值**降序**（高优先级覆盖低优先级）；
2. 同优先级下 **deny 优先于 allow**（fail-closed，避免同优先级冲突时放行）；
3. 同优先级、同效果下按 `rule_id` **字典序**（消除一切不确定性）。

例如同优先级的 allow 与 deny 同时命中时，结论恒为 deny；`trace` 中会打印排序后的
完整命中顺序与最终裁决规则。加载期还有一道更强的检查：**匹配范围与优先级完全相同、
效果相反的规则对属于不可裁决的语义矛盾，会直接拒绝整个版本**（区分于运行期可裁决的冲突）。

## 版本管理与校验

- 新版本经过「解析（语法）→ 语义校验」全部通过后才登记，`activate` 通过一次引用原子交换生效；
  校验失败的版本不会被登记，任何时刻都不会进入判定链路。
- 三类拒绝原因在错误类型与 API 状态码上均可区分：
  - **syntax_error（400）**：JSON/YAML 语法非法、顶层结构或字段类型错误；
  - **semantic_error（422）**：规则 id 重复、继承引用缺失、继承环（含自继承）、
    规则引用未定义主体/资源、同范围同优先级效果矛盾；details 一次性列出全部问题；
  - **duplicate_version（409）**：版本号与已加载版本重复（版本一旦登记不可覆盖，
    必须换版本号，避免就地变更导致结论不可追溯）。
- `rollback` 按激活栈恢复上一个生效版本（栈空时返回错误，不改变状态）。

## 项目结构

```
app/
  models.py     数据模型与拒绝原因分类
  parser.py     JSON/YAML 解析与语法层校验
  validator.py  语义校验（引用/环/矛盾）
  matcher.py    继承闭包、条件求值、确定性冲突裁决
  service.py    线程安全的版本库：加载/切换/回滚/判定
  api.py        FastAPI 接口
policies/       示例策略包 v1 / v2
tests/          解析校验、求值、并发切换回滚、HTTP 接口测试
main.py         启动入口（自动加载 policies/）
```
