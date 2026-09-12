# Traffic Rules（被动流量规则层）

> 定位（设计文档 §31）：一切经过 gateway 的流量旁路进规则扫描，命中产出 **PassiveHit（线索）**，升级必须带证据过三问门。**命中永远不是漏洞结论。**

## 文件

| 文件 | 来源 | 内容 |
|---|---|---|
| `xiasql-core.yaml` | 自研 xiasql 插件（`bp extension/sql/sankai-xiasql/h4nsec-xiasql-codex-Claude`）正式提取 | ORDER BY 注入评判规则（字段名/方向名两级判定 + 归一化 + 响应侧确认） |
| `hae-subset.yaml` | 按 gh0stkey/HaE 公开分类重建（待联网同步官方 Rules.yml 后替换） | 凭据/敏感信息/内网地址正则子集 |

## PassiveHit/v1 契约

```yaml
schema: PassiveHit/v1
rule_id: <规则id>
target: <host>
endpoint: <method + path>
param: <参数名或 null>
evidence_ref: <命中的请求/响应证据指针>
confidence: hint | candidate | urgent   # hint 仅记录；candidate 进 HighValueQueue；urgent 立即 P0 通知
matched_text: <命中片段，截断≤200字符>
created_at: <iso>
```

## 纪律

1. 新规则必须带 `source`（来源）与 `rationale`（为什么这个特征值得标记）；外部规则过 external-knowledge-sourcing 双审。
2. 规则只产出线索，**不得携带自动投递的攻击 payload**。
3. 规则通用性契约（§35 RuleContract）：命名变体（驼峰/下划线/短横线）兼容、多轮 URL 解码兼容、JSON 嵌套展平兼容。
4. 误报治理：某规则"命中→confirmed"转化率过低时进入 RuleAuditor 审计（§31.2），收紧后 SuccessCase 回放验证。
