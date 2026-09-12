#!/usr/bin/env python3
"""多 provider 池 OpenAI 兼容 chat 客户端（stdlib urllib，零依赖）。

凭据纪律：LLM_PROVIDERS 或旧版 LLM_API_KEY/LLM_BASE_URL/LLM_MODEL 只从环境变量
读取，绝不写入代码、日志或返回值。

- provider 池：LLM_PROVIDERS="name|base_url|api_key|model,name2|base2|key2|model2"。
  未设置时回退单组 LLM_API_KEY/LLM_BASE_URL/LLM_MODEL。调用失败自动故障转移到
  下一 provider（含 401/404 端点路径探测）。活跃 provider 可由 webui
  （POST /api/v1/model/active）写 model_active_provider.json 运行时切换：
  _providers() 每次调用重读该文件并把活跃 provider 提到 failover 队首，无需重启。
- 工具协议（主）：provider 原生 function calling（OpenAI 兼容 tools/tool_calls，
  DeepSeek 官方支持）。assistant.tool_calls → 本地执行 → role:tool 回灌 →
  二次生成最终回复。结构化字段触发，不依赖模型"自觉"写首行 JSON——
  自造文本协议触发不确定（ls 被编答案）是历史根因。
- 工具协议（fallback）：provider 不支持 tools（HTTP 400/422）时自动降级为
  自造"首行 {"action": ...}"文本协议（两轮调用制），行为与旧版一致。
- exec 工具（黑名单模式，2026-08-08 用户拍板自用放开）：固定 cwd（EXEC_WORKDIR，
  默认 /opt/pentest-agent，不存在则创建，创建失败回退系统临时目录，全失败返回
  明确错误文本拒绝执行）；默认放行所有命令，仅 danger_reason() 判定为真正危险
  的拒绝（rm -rf 根、mkfs、dd of=/dev/、shutdown/reboot/halt、fork bomb、
  chmod -R 777 /、写 /etc /root/.ssh 等）；sudo 放行但记审计 JSONL；
  重定向 > 仅允许落盘 tool-output 目录 / 工作目录 / /dev/null。
  注意：这是面向"白名单信任用户本人"的 shell，调用方必须保证只有信任用户
  能触发（feishu_reply_consumer 的 FEISHU_TRUSTED_USERS 门槛）。
- exec 输出机制：≤3000 字符全文直出；超阈值全文落盘 tool-output/<uuid>.txt，
  回灌模型的文本 = 前 2000 字符 + [截断，全文已存 <路径>，可发文件给你] +
  尾 500 字符（防上下文爆同时保留证据路径，反截断幻觉铁律见 SYSTEM_PROMPT）。
- per-user 对话历史：内存 dict，每用户保留最近 12 条消息，30 分钟无活动清空。
- 能力单一来源（core/capabilities.py CapabilityRegistry）：TOOL_DEFS 与系统提示
  能力清单都由注册表生成；斜杠命令与模型工具同一实现；通道上下文（chat_id/
  file_sender/task_manager）由消费进程经 set_chat_context 注入。
- 响应完整性硬约束：回复文本含承诺词（我去/让我统计/稍等 等）且无 tool_calls 时
  自动追问一轮，防"说了不做"；首轮与工具轮后的最终轮都兜住。
- 未配置或全部 provider 失败时 chat() 返回 None（调用方负责降级回复）。

用法：
  python core/model_client.py --self-test   # 无 key 时验证降级/故障转移路径，不打真实 API
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from core import capabilities
except ImportError:  # 直接以脚本方式运行（--self-test）
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core import capabilities

SYSTEM_PROMPT = (
    "你是渗透agent小夏。你说话直接给结论，不重复合规废话；在授权边界内可以做事。\n"
    "铁律：事实类问题（目录内容、当前时间、系统状态、文件内容、目标列表等）"
    "必须调用工具获取真实结果，禁止凭记忆或猜测编造命令输出、目录列表或文件内容。\n"
    "铁律（截断防幻觉）：工具输出被截断时（含 '[截断' 标记），必须明示"
    "'基于前N字符的截断部分'，禁止把截断部分当完整事实下结论（例如 ps 输出截断"
    "到某个 PID，不能得出'系统没有其他进程'的结论）；全文已自动落盘，需要全文时"
    "直接调用 send_file 把文件发给用户，或告诉用户文件路径让其发 /file <路径>。\n"
    "回复风格：先原样贴出工具的关键输出，解读放在原样输出之后并标注 [解读]。\n"
    "可用工具（function calling，由能力注册表 core/capabilities.py 自动生成）：\n"
    + capabilities.REGISTRY.capability_prompt() + "\n"
    "能力硬约束：你已具备上面列出的全部能力（含 send_file 发文件、run_pentest_task "
    "下渗透任务、read_file 读文件、search_docs 搜文档）；禁止声称'我没有文件上传接口/"
    "需要 API 凭证/做不到'——需要时直接调用对应工具；工具返回错误时把错误原样转述给用户。\n"
    "说到做到硬约束：不要在回复里承诺'我去查/我找一下/稍等'却不调用工具；要么立即调用"
    "工具执行，要么明确说明无法执行及原因。\n"
    "工具执行结果会回给你，你再基于真实结果给出最终结论。不需要工具时直接回复结论文本。\n"
    "（兼容协议：若当前环境没有工具接口，需要用工具时回复第一行独占输出一个 JSON 动作：\n"
    '{"action": "exec", "command": "<命令>"} / {"action": "status"} / '
    '{"action": "list_goals"} / {"action": "schedule", "minutes": <分钟>, "text": "<任务>"}，'
    "系统执行后回灌结果；不需要工具时不要输出任何 JSON。）"
)

# 响应完整性硬约束：无 tool_calls 但文本含承诺词 → 自动追问一轮（防"说了不做"）。
# 词表只匹配"承诺未来动作"形态（让我统计/我先确认/容我 等），不匹配完成式回答
# （"已为你统计如下"不含任何承诺词形，不会误判）。
# "让我<动词>"泛化覆盖（让我获取/让我跑一下 等无法穷举的动词），
# 否定后顾排除使役用法（"这让我想到/你让我觉得"不是承诺）。
PROMISE_RE = re.compile(
    r"(我去|我找一下|我来查|我查一下|我去查|我这就|稍等|我看一下|我看看"
    r"|让我看看|让我统计|让我查|让我确认|让我分析|让我先"
    r"|我先确认|我先看|我先查|我先统计"
    r"|我来分析|我来统计|我来确认|我帮你查|我帮你统计|我来帮你"
    r"|先查一下|先看一下|容我"
    r"|(?<![这那它你他她您])让我[一-龥]{1,8})")
PROMISE_FOLLOWUP_PROMPT = (
    "你刚才的回复承诺要去执行某个动作（查询/检查/发送等），但没有实际调用工具。"
    "请现在直接调用对应工具完成它；若确实无法执行，明确说明原因。禁止只承诺不执行。")

HISTORY_LIMIT = int(os.environ.get("LLM_HISTORY_LIMIT", "40"))  # 每用户保留最近消息条数(env可调)
HISTORY_TTL_SEC = 30 * 60   # 30 分钟无活动清空该用户历史
EXEC_OUTPUT_LIMIT = 4000    # 回灌模型的工具结果 JSON 总上限（防上下文爆）
EXEC_OUTPUT_FULL_LIMIT = 3000   # ≤此值全文直出；超阈值全文落盘 + 截断版回灌
EXEC_OUTPUT_HEAD = 2000     # 截断版保留前 N 字符
EXEC_OUTPUT_TAIL = 500      # 截断版保留尾 N 字符
EXEC_TIMEOUT_SEC = float(os.environ.get("EXEC_TIMEOUT_SEC", "30"))
LIST_GOALS_TAIL = 20        # list_goals 返回最近条数
SCHEDULE_MAX_MINUTES = 24 * 60

# ---------------- exec 黑名单（2026-08-08 用户拍板：默认放行，仅拦真正危险） ----------------
# rm -rf 保护根：带递归+强制的 rm 指向这些路径才拦（rm -rf /tmp/x 等普通清理放行）
_RM_PROTECTED_ROOTS = {
    "/", "/*", "~", "~/", "/home", "/etc", "/root", "/usr", "/var", "/boot",
    "/bin", "/lib", "/lib64", "/sbin", "/opt", "/srv", "/proc", "/sys", "/dev",
}
# 禁止写入的路径前缀（重定向/tee/cp/mv/sed -i 目标命中即拦）
_FORBIDDEN_WRITE_PREFIXES = (
    "/etc", "/root/.ssh", "/root/.bashrc", "/root/.profile", "/root/.bash_profile",
    "/boot", "/sys", "/proc", "/dev/",
)
# 关机/电源类命令名（作为分段首 token 命中即拦）
_POWER_COMMANDS = {"shutdown", "reboot", "halt", "poweroff", "telinit"}
# 磁盘毁灭类命令名（分段首 token 命中即拦；mkfs.* 系列另按前缀匹配）
_DISK_DESTROY_COMMANDS = {"fdisk", "wipefs", "badblocks", "sgdisk", "parted"}

# function calling 工具定义：由能力注册表自动生成（单一来源 core/capabilities.py，
# 加能力只改注册表一处，TOOL_DEFS 与系统提示同步更新）
TOOL_DEFS: List[Dict[str, Any]] = capabilities.REGISTRY.tool_defs()

# 单次 chat 允许的最大 tool_calls 轮次（防死循环）。
# 2026-08-09 由 3 提至 6：实测"整理 docs"类多步任务（截断→读全文→再统计）
# 需要 4-5 轮工具调用，3 轮耗尽后未执行的 tool_calls 文本被当最终回复悬空返回。
MAX_TOOL_ROUNDS = 6

_histories: Dict[str, List[dict]] = {}
_last_active: Dict[str, float] = {}
# 消费进程注入的 per-user 调用上下文（chat_id/file_sender/task_manager），
# send_file/run_pentest_task 等通道能力依赖
_contexts: Dict[str, "capabilities.CapabilityContext"] = {}


def set_chat_context(user_id: str, *, chat_id: str = "",
                     file_sender: Optional[Any] = None,
                     task_manager: Optional[Any] = None,
                     source: str = "", engagement_target: str = "") -> None:
    """消费进程在调用 chat() 前注入通道上下文（send_file 需 chat_id+file_sender；
    engagement_target = 当前授权渗透目标,供语义门台账/scope 用）。"""
    _contexts[user_id] = capabilities.CapabilityContext(
        user_id=user_id, chat_id=chat_id, file_sender=file_sender,
        task_manager=task_manager, source=source, engagement_target=engagement_target)


def get_chat_context(user_id: str) -> "capabilities.CapabilityContext":
    return _contexts.get(user_id) or capabilities.CapabilityContext(user_id=user_id)


# ---------------- provider 池 ----------------

def _legacy_config() -> Dict[str, str]:
    return {
        "api_key": os.environ.get("LLM_API_KEY", "").strip(),
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.deepseek.com").strip().rstrip("/"),
        "model": os.environ.get("LLM_MODEL", "deepseek-chat").strip(),
    }


def _parse_providers() -> List[Dict[str, str]]:
    """解析 LLM_PROVIDERS 池；未设置时回退旧版单组配置。无 key 的组直接丢弃。"""
    providers: List[Dict[str, str]] = []
    raw = os.environ.get("LLM_PROVIDERS", "").strip()
    if raw:
        for i, group in enumerate(raw.split(",")):
            parts = [p.strip() for p in group.split("|")]
            if len(parts) != 4:
                continue
            name, base, key, model = parts
            if not key:
                continue
            providers.append({
                "name": name or f"provider-{i}",
                "base_url": (base or "https://api.deepseek.com").rstrip("/"),
                "api_key": key,
                "model": model or "deepseek-chat",
            })
    if not providers:
        cfg = _legacy_config()
        if cfg["api_key"]:
            providers.append({
                "name": "default",
                "base_url": cfg["base_url"],
                "api_key": cfg["api_key"],
                "model": cfg["model"],
            })
    return providers


# ---------------- 目标/定时任务持久化文件 ----------------

def goals_file() -> Path:
    return Path(os.environ.get("GOALS_FILE", "goals.jsonl"))


def loop_tasks_file() -> Path:
    return Path(os.environ.get("LOOP_TASKS_FILE", "loop_tasks.jsonl"))


# ---------------- 活跃 provider（R2 运行时切换，非只读 env） ----------------

def active_provider_file() -> Path:
    """活跃 provider 状态文件：LLM_ACTIVE_PROVIDER_FILE env
    → /opt/pentest-agent/runtime/model_active_provider.json（webui control_plane 写入处）
    → goals 同级目录。文件只含 name/model/set_at，绝不含 key。"""
    raw = os.environ.get("LLM_ACTIVE_PROVIDER_FILE", "").strip()
    if raw:
        return Path(raw)
    runtime = Path("/opt/pentest-agent/runtime")
    if runtime.is_dir():
        return runtime / "model_active_provider.json"
    return goals_file().parent / "model_active_provider.json"


def get_active_provider_name() -> str:
    """读活跃 provider 名；文件缺失/损坏/无 name 时返回 ''（=不调整池顺序）。"""
    try:
        doc = json.loads(active_provider_file().read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - 状态文件问题绝不阻断调用
        return ""
    if not isinstance(doc, dict):
        return ""
    return str(doc.get("name", "")).strip()


def set_active_provider(name: str) -> Optional[Dict[str, str]]:
    """校验 name 命中当前池后原子写状态文件；返回命中 provider（脱敏，无 key）或 None。"""
    name = (name or "").strip()
    match = next((p for p in _parse_providers() if p.get("name") == name), None)
    if match is None:
        return None
    path = active_provider_file()
    doc = {"name": match["name"], "model": match["model"],
           "set_at": time.time(), "set_by": "model_client"}
    try:
        tmp = path.with_name("." + path.name + ".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return None
    return {"name": match["name"], "model": match["model"]}


def _providers() -> List[Dict[str, str]]:
    """池 + 活跃 provider 提队首：每次调用重读状态文件，webui 切换后下一次调用即生效。"""
    providers = _parse_providers()
    active = get_active_provider_name()
    if not active:
        return providers
    for i, p in enumerate(providers):
        if p.get("name") == active:
            return [p] + providers[:i] + providers[i + 1:]
    return providers


def _append_jsonl(path: Path, entry: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True) if str(path.parent) not in ("", ".") else None
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------------- 历史管理 ----------------

def _prune(user_id: str) -> None:
    now = time.time()
    for uid, ts in list(_last_active.items()):
        if now - ts > HISTORY_TTL_SEC:
            _histories.pop(uid, None)
            _last_active.pop(uid, None)
            # 一并回收 per-user 上下文，避免 _contexts 单调增长钉住 file_sender/task_manager 引用
            _contexts.pop(uid, None)
    hist = _histories.get(user_id, [])
    if len(hist) > HISTORY_LIMIT:
        _histories[user_id] = hist[-HISTORY_LIMIT:]


_last_usage: Dict[str, Any] = {}   # 最近一次调用的 usage(含 DeepSeek 前缀缓存命中数),供观测/省钱分析


def _record_usage(usage: Optional[Dict[str, Any]]) -> None:
    """记录 DeepSeek usage:prompt_cache_hit_tokens=前缀缓存命中(约 1/10 价),miss=未命中。
    我们的 system prompt 已是常量前缀(triage/verify/key-triage),天然吃缓存;这里只做观测。
    落盘需 env LLM_USAGE_LOG=1(默认关,不影响热路径)。"""
    if not usage:
        return
    try:
        _last_usage.clear()
        _last_usage.update(usage)
        if os.environ.get("LLM_USAGE_LOG", "").strip().lower() in ("1", "on", "true", "yes"):
            _append_jsonl(Path(os.environ.get("LLM_USAGE_LOG_FILE", "llm_usage.jsonl")), {
                "ts": time.time(),
                "cache_hit": usage.get("prompt_cache_hit_tokens"),
                "cache_miss": usage.get("prompt_cache_miss_tokens"),
                "prompt": usage.get("prompt_tokens"),
                "completion": usage.get("completion_tokens"),
                "total": usage.get("total_tokens"),
            })
    except Exception:  # noqa: BLE001 - 观测失败绝不影响主调用
        pass


def _post_message(url: str, body: bytes, api_key: str, timeout: float) -> Dict[str, Any]:
    """POST chat/completions，返回完整 message dict（content + tool_calls）。"""
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    _record_usage(data.get("usage"))   # 观测前缀缓存命中(不改返回值/不影响调用方)
    return data["choices"][0].get("message") or {}


def _post(url: str, body: bytes, api_key: str, timeout: float) -> str:
    return ((_post_message(url, body, api_key, timeout).get("content")) or "").strip()


def _call_via_litellm(provider: Dict[str, str], messages: List[dict], timeout: float,
                      tools: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """opt-in：用成熟开源 litellm 统一接口调用（预期7 二开轮子）。litellm 未安装或
    调用失败 → 返回 None，调用方回退到自研 urllib 路径（保证在跑的对话零风险）。
    后续 AI：全量切到 litellm(Router/fallbacks) 时，把 _providers 池映射成 litellm
    的 model_list + Router，替换 _call_with_failover_msg；此处是安全的渐进接入点。"""
    try:
        import litellm  # type: ignore
    except ImportError:
        return None
    try:
        kwargs: Dict[str, Any] = {
            "model": provider["model"], "messages": messages,
            "api_key": provider["api_key"],
            "api_base": provider["base_url"].rstrip("/"),
            "temperature": 0.3, "timeout": timeout,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        resp = litellm.completion(**kwargs)
        choice = resp.choices[0].message
        content = getattr(choice, "content", None) or ""
        msg: Dict[str, Any] = {"role": "assistant", "content": content}
        raw_tc = getattr(choice, "tool_calls", None)
        if raw_tc:
            out = []
            for x in raw_tc:
                if isinstance(x, dict):
                    out.append(x)
                elif hasattr(x, "model_dump"):
                    out.append(x.model_dump())
                elif hasattr(x, "dict"):
                    out.append(x.dict())
            if out:
                msg["tool_calls"] = out
        if content.strip() or msg.get("tool_calls"):
            return msg
        return None
    except Exception:
        return None


def _call_provider(provider: Dict[str, str], messages: List[dict], timeout: float,
                   tools: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """单 provider 尝试，返回 message dict（含 tool_calls）或 None。

    端点路径兼容：base 已含 /v1 则直接用；否则先试 /v1/chat/completions，
    401/404 再退 /chat/completions（one-api 类自建网关实测差异）。
    tools 不被支持（HTTP 400/422）时自动降级为无 tools 重试（走文本协议 fallback）。
    """
    # opt-in litellm（预期7）：默认关，LLM_USE_LITELLM=1 才启用；未装/失败自动回退。
    if os.environ.get("LLM_USE_LITELLM", "").strip().lower() in ("1", "true", "on", "yes"):
        lit = _call_via_litellm(provider, messages, timeout, tools)
        if lit is not None:
            return lit  # litellm 成功；否则落回下面自研路径（不中断在跑对话）
    base = provider["base_url"].rstrip("/")
    paths = ["/chat/completions"] if base.endswith("/v1") else [
        "/v1/chat/completions", "/chat/completions"]
    payload: Dict[str, Any] = {
        "model": provider["model"],
        "messages": messages,
        "temperature": 0.3,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    body = json.dumps(payload).encode("utf-8")
    for path in paths:
        try:
            msg = _post_message(base + path, body, provider["api_key"], timeout)
            if (msg.get("content") or "").strip() or msg.get("tool_calls"):
                return msg
            return None  # 空内容：换下一 provider
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 404) and path != paths[-1]:
                continue  # 换无 /v1 路径再试
            if tools and exc.code in (400, 422):
                # provider 不支持 tools 参数：降级无 tools 重试（自造文本协议 fallback）
                return _call_provider(provider, messages, timeout, tools=None)
            return None  # 其他 HTTP 错误：换下一 provider
        except Exception:
            return None  # 网络/解析错误：换下一 provider
    return None


def _call_with_failover_msg(providers: List[Dict[str, str]], messages: List[dict],
                            timeout: float,
                            tools: Optional[List[Dict[str, Any]]] = None
                            ) -> Optional[Dict[str, Any]]:
    """按池顺序调用，失败自动故障转移。返回 message dict 或 None。"""
    for provider in providers:
        msg = _call_provider(provider, messages, timeout, tools=tools)
        if msg is not None:
            return msg
    return None


def _call_with_failover(providers: List[Dict[str, str]], messages: List[dict],
                        timeout: float) -> Optional[str]:
    """旧接口：只取文本 content（用于 fallback 文本协议第二轮）。"""
    msg = _call_with_failover_msg(providers, messages, timeout)
    if msg is None:
        return None
    return (msg.get("content") or "").strip() or None


def complete(system: str, user: str, *, timeout: float = 60.0, prefer: str = "",
             only: bool = False) -> Optional[str]:
    """无状态一次性补全（复用 provider 池 + 故障转移）。供情报质量门、PoC 追溯等 LLM
    判断任务复用（用户预期：情报默认走一层 DeepSeek 深度分析再决定是否播报）。

    prefer：子串命中 name/model 的 provider 提到最前（如 prefer='deepseek'）。
    only=True：**只用** prefer 命中的 provider，不故障转移到其它模型——用于"换个模型答案
    就不对"的任务(如情报判定:DeepSeek 限流时宁可返 None 下轮重试,也不要 grok 的保守错答)。
    无 provider/全失败 → None。"""
    providers = _providers()
    if not providers:
        return None
    if prefer:
        p = prefer.lower()
        match = [x for x in providers if p in (x.get("name", "") + x.get("model", "")).lower()]
        if only:
            providers = match  # 只用命中的,不 failover 到别的模型
        elif match:
            rest = [x for x in providers if x not in match]
            providers = match + rest  # 命中的优先,失败再 failover
    if not providers:
        return None
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    return _call_with_failover(providers, messages, timeout)


# ---------------- 最小工具协议 ----------------

def parse_action(content: str) -> Optional[Dict[str, Any]]:
    """模型回复首行以 {"action": 开头则解析为动作；否则返回 None（纯文本回复）。"""
    if not content or not content.strip():
        return None
    first = content.lstrip().splitlines()[0].strip()
    if not first.startswith('{"action"'):
        return None
    try:
        obj = json.loads(first)
    except json.JSONDecodeError:
        return None  # 不完整 JSON 不当动作，按普通文本回复处理
    if not isinstance(obj, dict) or "action" not in obj:
        return None
    return obj


def exec_workdir() -> Optional[Path]:
    """exec 固定工作目录：EXEC_WORKDIR env → 默认 /opt/pentest-agent → 系统临时目录回退。

    候选目录不存在则尝试创建；全部不可用返回 None（调用方必须拒绝执行并给明确错误）。
    """
    candidates: List[Path] = []
    env_dir = os.environ.get("EXEC_WORKDIR", "").strip()
    if env_dir:
        candidates.append(Path(env_dir))
    if os.name != "nt":
        candidates.append(Path("/opt/pentest-agent"))
    candidates.append(Path(tempfile.gettempdir()) / "pentest-agent-exec")
    for cand in candidates:
        try:
            if cand.is_dir():
                return cand
            cand.mkdir(parents=True, exist_ok=True)
            return cand
        except OSError:
            continue
    return None


def tool_output_dir() -> Optional[Path]:
    """工具输出全文落盘目录：TOOL_OUTPUT_DIR env → /opt/pentest-agent/runtime/tool-output
    → <exec_workdir>/runtime/tool-output → 系统临时目录。全不可用返回 None。"""
    candidates: List[Path] = []
    env_dir = os.environ.get("TOOL_OUTPUT_DIR", "").strip()
    if env_dir:
        candidates.append(Path(env_dir))
    if os.name != "nt":
        candidates.append(Path("/opt/pentest-agent/runtime/tool-output"))
    wd = exec_workdir()
    if wd is not None:
        candidates.append(wd / "runtime" / "tool-output")
    candidates.append(Path(tempfile.gettempdir()) / "pentest-agent-tool-output")
    for cand in candidates:
        try:
            if cand.is_dir():
                return cand
            cand.mkdir(parents=True, exist_ok=True)
            return cand
        except OSError:
            continue
    return None


def exec_audit_file() -> Path:
    """exec 审计文件：EXEC_AUDIT_FILE env → tool-output 同级 runtime/exec_audit.jsonl。"""
    env_path = os.environ.get("EXEC_AUDIT_FILE", "").strip()
    if env_path:
        return Path(env_path)
    out = tool_output_dir()
    if out is not None:
        return out.parent / "exec_audit.jsonl"
    return Path(tempfile.gettempdir()) / "pentest-agent-exec-audit.jsonl"


def _audit_exec(entry: Dict[str, Any]) -> None:
    try:
        _append_jsonl(exec_audit_file(), entry)
    except Exception:
        pass


def format_tool_output(output: str) -> Dict[str, Any]:
    """≤EXEC_OUTPUT_FULL_LIMIT 全文直出；超阈值全文落盘 tool-output/<uuid>.txt，
    返回 前2000 + [截断，全文已存 <路径>，可发文件给你] + 尾500。"""
    if len(output) <= EXEC_OUTPUT_FULL_LIMIT:
        return {"output": output, "truncated": False}
    out_dir = tool_output_dir()
    saved_path = ""
    if out_dir is not None:
        try:
            fpath = out_dir / (uuid.uuid4().hex + ".txt")
            fpath.write_text(output, encoding="utf-8", errors="replace")
            saved_path = str(fpath)
        except OSError:
            saved_path = ""
    marker = (f"\n[截断，共 {len(output)} 字符，全文已存 {saved_path}，可发文件给你]\n"
              if saved_path else
              f"\n[截断，共 {len(output)} 字符，落盘失败仅保留首尾]\n")
    return {"output": output[:EXEC_OUTPUT_HEAD] + marker + output[-EXEC_OUTPUT_TAIL:],
            "truncated": True, "total_chars": len(output),
            "full_output_file": saved_path}


_SHELL_META = re.compile(r"[>|&;`$\n]")


def _redirect_targets(command: str) -> List[str]:
    """提取重定向目标（> >> 2> &> 等）与 tee 的写目标，用于落盘范围判定。"""
    targets: List[str] = []
    for m in re.finditer(r"\d*>{1,2}\s*(\"[^\"]+\"|'[^']+'|[^\s;|&<>]+)", command):
        targets.append(m.group(1).strip("'\""))
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    for i, tok in enumerate(tokens):
        if os.path.basename(tok) == "tee":
            for t in tokens[i + 1:]:
                if not t.startswith("-"):
                    targets.append(t)
    return targets


def danger_reason(command: str, workdir: Optional[Path] = None) -> Optional[str]:
    """黑名单判定（可测纯函数）：命中返回拒绝原因，否则 None 放行。

    只拦真正危险：rm -rf 保护根、mkfs/fdisk 类、dd of=/dev/、shutdown/reboot/halt、
    fork bomb、chmod -R 777 根、写 /etc /root/.ssh 等；重定向只允许落盘
    tool-output 目录 / 工作目录 / /dev/null。
    """
    if not command or not command.strip():
        return "empty_command"
    if workdir is None:
        workdir = exec_workdir()
    squashed = re.sub(r"\s+", "", command)
    # fork bomb：:(){:|:&};: 及其空白变体
    if re.search(r":\(\)\{.*:\|.*:&.*\};:", squashed):
        return "fork_bomb"
    # dd 写块设备
    if re.search(r"\bof=/dev/", command):
        return "dd_to_device"
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    base_tokens = [os.path.basename(t) for t in tokens]
    # 电源/磁盘毁灭类命令（任意分段首 token 或出现即拦，宁可误拦）
    for tok in base_tokens:
        if tok in _POWER_COMMANDS or tok in _DISK_DESTROY_COMMANDS or tok.startswith("mkfs"):
            return f"denied_command:{tok}"
    if "systemctl" in base_tokens:
        for t in base_tokens:
            if t in ("poweroff", "reboot", "halt", "kexec"):
                return "power_control"
    if "init" in base_tokens:
        idx = base_tokens.index("init")
        if idx + 1 < len(tokens) and tokens[idx + 1] in ("0", "6"):
            return "power_control"
    # rm -rf 保护根
    if "rm" in base_tokens:
        idx = base_tokens.index("rm")
        flags = "".join(t.lstrip("-") for t in tokens[idx + 1:] if t.startswith("-"))
        targets = [t.rstrip("/") or "/" for t in tokens[idx + 1:] if not t.startswith("-")]
        if "r" in flags and "f" in flags:
            for t in targets:
                if t in _RM_PROTECTED_ROOTS or t in ("~",) or t.startswith("/root/.ssh"):
                    return "rm_rf_protected_root"
    # chmod -R 777 根 / chown -R 根
    for name in ("chmod", "chown", "chgrp"):
        if name in base_tokens:
            idx = base_tokens.index(name)
            seg = tokens[idx + 1:]
            recursive = any(t.startswith("-") and "R" in t for t in seg)
            targets = [t.rstrip("/") or "/" for t in seg if not t.startswith("-")]
            if name == "chmod" and not any(t == "777" for t in seg):
                continue
            if recursive and any(t in _RM_PROTECTED_ROOTS for t in targets):
                return f"{name}_recursive_root"
    # 写保护路径：重定向 / tee / sed -i / cp / mv / install 目标命中 /etc /root/.ssh 等
    write_targets = list(_redirect_targets(command))
    for name in ("sed", "cp", "mv", "install", "ln", "crontab"):
        if name in base_tokens:
            idx = base_tokens.index(name)
            seg = [t for t in tokens[idx + 1:] if not t.startswith("-")]
            if name == "sed" and "-i" not in tokens[idx + 1:] and not any(
                    t.startswith("-i") for t in tokens[idx + 1:]):
                continue
            if name == "crontab":
                write_targets.append("/etc/crontab")
                continue
            if seg:
                write_targets.append(seg[-1])  # 目标惯例在最后
    out_dir = tool_output_dir()
    for raw in write_targets:
        if raw in ("/dev/null", "null", "-"):
            continue
        # 保护路径按原始字符串判定（目标是 Linux VPS，/etc 等前缀语义与运行平台无关）
        if raw.startswith("/") and any(
                raw == pref.rstrip("/") or raw.startswith(pref)
                for pref in _FORBIDDEN_WRITE_PREFIXES):
            return "write_protected_path"
        p = Path(raw)
        if not p.is_absolute() and workdir is not None:
            p = workdir / p
        s = str(p).replace("\\", "/")
        if any(s == pref.rstrip("/") or s.startswith(pref) for pref in _FORBIDDEN_WRITE_PREFIXES):
            return "write_protected_path"
        # 重定向落盘范围：仅 tool-output 目录 / 工作目录（tee 同样约束，防任意写）
        resolved_ok = False
        for base in (out_dir, workdir):
            if base is None:
                continue
            try:
                p_res = p.resolve() if not p.is_absolute() else p
                p_res.relative_to(base.resolve())
                resolved_ok = True
                break
            except (OSError, ValueError):
                continue
        if not resolved_ok:
            return "write_outside_allowed_dirs"
    return None


def _exec_command(command: str) -> Dict[str, Any]:
    """黑名单模式命令执行。固定 cwd；危险判定走 danger_reason；sudo 放行但记审计。"""
    workdir = exec_workdir()
    if workdir is None:
        return {"ok": False,
                "error": "workdir_unavailable: 执行目录不存在且无法创建/回退，已拒绝执行"}
    reason = danger_reason(command, workdir=workdir)
    if reason is not None:
        if reason != "empty_command":
            _audit_exec({"ts": time.time(), "command": command[:500],
                         "result": "denied", "reason": reason})
        return {"ok": False, "error": f"dangerous_denied:{reason}"}
    try:
        args = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        args = []
    cmd = os.path.basename(args[0]) if args else ""
    rest = args[1:]
    # sudo 放行但记审计（含整条命令，截断 500 字符）
    uses_sudo = "sudo" in [os.path.basename(t) for t in args]
    if uses_sudo:
        _audit_exec({"ts": time.time(), "command": command[:500],
                     "result": "allowed_sudo"})
    shell_mode = bool(_SHELL_META.search(command))
    # 无 shell 元字符时的原生快捷实现（跨平台一致语义，Windows 自测可跑）
    if not shell_mode:
        if cmd == "echo":
            return {"ok": True, "output": " ".join(rest)}
        if cmd == "pwd":
            return {"ok": True, "output": str(workdir)}
        if cmd == "ls":
            try:
                proc = subprocess.run(["ls"] + rest, capture_output=True, text=True,
                                      timeout=EXEC_TIMEOUT_SEC, cwd=str(workdir))
                output = (proc.stdout or "") + (proc.stderr or "")
            except FileNotFoundError:
                # 无 ls 二进制的平台（如 Windows 裸环境）：原生兜底，跳过 - 开头 flag
                paths = [a for a in rest if not a.startswith("-")] or ["."]
                try:
                    entries = sorted(os.listdir(workdir / paths[0]))[:200]
                    return {"ok": True, **format_tool_output("\n".join(entries))}
                except OSError as exc:
                    return {"ok": False, "error": type(exc).__name__}
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"ok": False, "error": type(exc).__name__}
            return {"ok": proc.returncode == 0, **format_tool_output(output.strip()),
                    "returncode": proc.returncode}
        if cmd == "cat":
            if len(rest) != 1:
                return {"ok": False, "error": "usage: cat <file>"}
            path = Path(rest[0])
            if not path.is_absolute():
                path = workdir / path
            try:
                with path.open(encoding="utf-8", errors="replace") as f:
                    return {"ok": True, **format_tool_output(f.read(200000))}
            except OSError as exc:
                return {"ok": False, "error": type(exc).__name__}
    # 通用路径：shell 执行（posix /bin/sh -c；nt cmd）。含 >|&; 等元字符也走这里，
    # 重定向目标已被 danger_reason 限定在 tool-output / workdir / /dev/null。
    try:
        if os.name == "nt":
            proc = subprocess.run(command, shell=True, capture_output=True, text=True,
                                  timeout=EXEC_TIMEOUT_SEC, cwd=str(workdir))
        else:
            proc = subprocess.run(["/bin/sh", "-c", command], capture_output=True,
                                  text=True, timeout=EXEC_TIMEOUT_SEC, cwd=str(workdir))
        output = (proc.stdout or "") + (proc.stderr or "")
        return {"ok": proc.returncode == 0, **format_tool_output(output.strip()),
                "returncode": proc.returncode}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__}


def execute_action(action: Dict[str, Any]) -> Dict[str, Any]:
    """执行解析出的动作，返回结构化结果（用于回灌模型与审计）。"""
    name = str(action.get("action", ""))
    if name == "exec":
        result = _exec_command(str(action.get("command", "")))
        result["action"] = "exec"
        return result
    if name == "status":
        return {"action": "status", "ok": True, "time": int(time.time()),
                "goals_file": str(goals_file()),
                "loop_tasks_file": str(loop_tasks_file()),
                "active_users": len(_histories)}
    if name == "list_goals":
        path = goals_file()
        if not path.exists():
            return {"action": "list_goals", "ok": True, "goals": []}
        try:
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            goals = [json.loads(l) for l in lines[-LIST_GOALS_TAIL:] if l.strip()]
            return {"action": "list_goals", "ok": True, "goals": goals}
        except Exception as exc:
            return {"action": "list_goals", "ok": False, "error": type(exc).__name__}
    if name == "schedule":
        text = str(action.get("text", "")).strip()
        try:
            minutes = float(action.get("minutes", 0))
        except (TypeError, ValueError):
            minutes = 0
        if not text or minutes <= 0 or minutes > SCHEDULE_MAX_MINUTES:
            return {"action": "schedule", "ok": False,
                    "error": "usage: schedule <minutes 1-1440> <text>"}
        entry = {"ts": time.time(), "interval_min": minutes, "task": text,
                 "next_due_ts": time.time() + minutes * 60, "source": "model_action"}
        try:
            _append_jsonl(loop_tasks_file(), entry)
            return {"action": "schedule", "ok": True, "scheduled": entry}
        except OSError as exc:
            return {"action": "schedule", "ok": False, "error": type(exc).__name__}
    return {"ok": False, "error": "unknown_action"}


# ---------------- function calling 工具分发 ----------------

def execute_tool(name: str, arguments: Dict[str, Any],
                 ctx: "Optional[capabilities.CapabilityContext]" = None) -> Dict[str, Any]:
    """function calling 工具名 → 能力注册表统一执行（与斜杠命令同一实现）。"""
    return capabilities.REGISTRY.execute(name, arguments, ctx)


def _forced_final_summary(convo: List[dict], current: Dict[str, Any],
                          providers: List[Dict[str, str]], timeout: float) -> Optional[str]:
    """工具轮次耗尽/生成中断时的兜底：不带 tools 追加收尾指令，强制模型基于
    已收集的工具结果直接总结，避免把中间叙事或未执行的 tool_calls 文本悬空返回。"""
    closing = convo + [
        {"role": "assistant",
         "content": (current.get("content") or "").strip() or "（工具调用轮次已达上限）"},
        {"role": "user", "content":
            "工具调用轮次已达上限，禁止再调用工具或承诺'我去查/让我看看'类未执行动作。"
            "请基于上面已获得的工具结果直接给出最终回复：先原样贴出关键输出，"
            "再给出 [解读]；信息不完整时明确说明已覆盖的范围。"}]
    msg = _call_with_failover_msg(providers, closing, timeout)  # 不带 tools
    if msg is None:
        return None
    return (msg.get("content") or "").strip() or None


def _run_tool_calls(messages: List[dict], msg: Dict[str, Any],
                    providers: List[Dict[str, str]], timeout: float,
                    ctx: "Optional[capabilities.CapabilityContext]" = None
                    ) -> Tuple[Optional[str], List[str], List[dict]]:
    """assistant.tool_calls → 本地执行 → role:tool 回灌 → 二次生成。

    返回 (最终文本或 None, 已执行工具名列表, 完整对话 convo)。
    最多 MAX_TOOL_ROUNDS 轮防死循环；轮次耗尽或生成中断时强制无 tools 收尾总结。
    convo 供调用方做最终轮承诺词追问。
    """
    used: List[str] = []
    current = msg
    convo = list(messages)
    for _ in range(MAX_TOOL_ROUNDS):
        tool_calls = current.get("tool_calls") or []
        if not tool_calls:
            return ((current.get("content") or "").strip() or None), used, convo
        convo.append({"role": "assistant",
                      "content": current.get("content") or "",
                      "tool_calls": tool_calls})
        for call in tool_calls[:4]:  # 单轮最多执行 4 个调用，防刷
            fn = call.get("function") or {}
            name = str(fn.get("name", ""))
            try:
                arguments = json.loads(fn.get("arguments") or "{}")
                if not isinstance(arguments, dict):
                    arguments = {}
            except json.JSONDecodeError:
                arguments = {}
            result = execute_tool(name, arguments, ctx)
            used.append(name)
            convo.append({"role": "tool",
                          "tool_call_id": str(call.get("id", "")),
                          "content": json.dumps(result, ensure_ascii=False)[:EXEC_OUTPUT_LIMIT]})
        nxt = _call_with_failover_msg(providers, convo, timeout, tools=TOOL_DEFS)
        if nxt is None:
            break  # 生成中断：走兜底收尾
        current = nxt
    final = (current.get("content") or "").strip()
    summary = _forced_final_summary(convo, current, providers, timeout)
    return (summary or final or None), used, convo


def _promise_followup(messages: List[dict], content: str,
                      providers: List[Dict[str, str]], timeout: float,
                      ctx: "Optional[capabilities.CapabilityContext]" = None
                      ) -> Optional[str]:
    """承诺词追问一轮：把承诺文本作为 assistant 消息 + 追问 prompt 回灌，
    模型可趁机真正调用工具。返回最终文本或 None（追问失败则保留原文）。
    只追问一轮，不递归（追问结果不再检查承诺词，总轮数受 MAX_TOOL_ROUNDS 约束）。
    """
    follow = messages + [
        {"role": "assistant", "content": content},
        {"role": "user", "content": PROMISE_FOLLOWUP_PROMPT}]
    msg2 = _call_with_failover_msg(providers, follow, timeout, tools=TOOL_DEFS)
    if msg2 is None:
        return None
    if msg2.get("tool_calls"):
        final2, _used2, _convo2 = _run_tool_calls(follow, msg2, providers, timeout, ctx)
        if final2:
            if parse_action(final2) is not None:
                rest = "\n".join(final2.lstrip().splitlines()[1:]).strip()
                final2 = rest or "已完成。"
            return final2
        return None
    return (msg2.get("content") or "").strip() or None


# ---------------- 对话主入口 ----------------

def chat(user_id: str, text: str, *, timeout: float = 30.0) -> Optional[str]:
    """对话一轮。主路径 function calling；provider 不支持 tools 时自动降级文本协议。"""
    providers = _providers()
    if not providers:
        return None
    _prune(user_id)
    hist = _histories.setdefault(user_id, [])
    hist.append({"role": "user", "content": text})
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + hist[-HISTORY_LIMIT:]

    msg = _call_with_failover_msg(providers, messages, timeout, tools=TOOL_DEFS)
    if msg is None:
        hist.pop()  # 请求失败不计入历史
        return None

    ctx = get_chat_context(user_id)

    # 主路径：结构化 tool_calls（触发由 API 字段保证，不靠模型自觉写首行 JSON）
    if msg.get("tool_calls"):
        final, used, convo = _run_tool_calls(messages, msg, providers, timeout, ctx)
        if final is None:
            final = "动作已执行（" + ",".join(used) + "），但生成最终回复失败。"
        else:
            if parse_action(final) is not None:
                # 最终回复仍带协议 JSON：剥离首行，避免泄漏给用户
                rest = "\n".join(final.lstrip().splitlines()[1:]).strip()
                final = rest or "已完成。"
            # 最终轮兜住：工具轮后收尾文本仍含承诺词且无后续 tool_calls → 追加一轮追问
            if PROMISE_RE.search(final):
                followed = _promise_followup(convo, final, providers, timeout, ctx)
                if followed:
                    final = followed
        hist.append({"role": "assistant", "content": final})
        _last_active[user_id] = time.time()
        _prune(user_id)
        return final

    content = (msg.get("content") or "").strip()

    # 响应完整性硬约束：首轮无 tool_calls 但文本含承诺词（我去/让我统计/稍等 等）
    # → 自动追问一轮（防"说了不做"）；追问后若模型调工具则执行并取最终结果。
    if parse_action(content) is None and PROMISE_RE.search(content):
        followed = _promise_followup(messages, content, providers, timeout, ctx)
        if followed:
            content = followed

    # fallback 路径：provider 不支持 tools，模型按文本协议输出首行 JSON 动作
    action = parse_action(content)
    if action is None:
        hist.append({"role": "assistant", "content": content})
        _last_active[user_id] = time.time()
        _prune(user_id)
        return content

    # 文本协议第二轮：动作执行结果回灌，生成最终回复
    result = execute_action(action)
    result_json = json.dumps(result, ensure_ascii=False)[:EXEC_OUTPUT_LIMIT]
    messages2 = messages + [
        {"role": "assistant", "content": content},
        {"role": "user", "content":
            "工具执行结果：" + result_json + "\n请基于结果直接给出最终回复（不要再输出 JSON 动作）。"},
    ]
    final = _call_with_failover(providers, messages2, timeout)
    if final is None:
        final = "动作已执行：" + result_json  # 第二轮全挂：至少把结果带回
    elif parse_action(final) is not None:
        # 第二轮仍输出动作 JSON：剥离首行，避免把协议泄漏给用户
        rest = "\n".join(final.lstrip().splitlines()[1:]).strip()
        final = rest or "已完成。"
    hist.append({"role": "assistant", "content": final})
    _last_active[user_id] = time.time()
    _prune(user_id)
    return final


def reset_history(user_id: str) -> None:
    _histories.pop(user_id, None)
    _last_active.pop(user_id, None)
    _contexts.pop(user_id, None)


def _self_test() -> int:
    saved = {k: os.environ.pop(k, None) for k in
             ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "LLM_PROVIDERS",
              "GOALS_FILE", "LOOP_TASKS_FILE", "EXEC_WORKDIR",
              "TOOL_OUTPUT_DIR", "EXEC_AUDIT_FILE", "LLM_ACTIVE_PROVIDER_FILE")}
    orig_post_msg = _post_message
    orig_workdir = exec_workdir
    try:
        # 1. 无任何配置时降级返回 None，不打真实 API
        assert chat("u1", "你好") is None
        # 2. 旧版单组配置兼容
        os.environ["LLM_BASE_URL"] = ""; os.environ.pop("LLM_BASE_URL", None)
        cfg = _legacy_config()
        assert cfg["base_url"] == "https://api.deepseek.com" and cfg["model"] == "deepseek-chat", cfg
        # 3. provider 池解析：name|base|key|model 逗号分隔多组，无 key 组丢弃
        os.environ["LLM_PROVIDERS"] = "p1|http://a|k1|m1, p2|http://b/v1|k2|m2, bad|http://c||m3, broken"
        pool = _providers()
        assert len(pool) == 2 and pool[0]["name"] == "p1" and pool[1]["model"] == "m2", pool
        # 3b. R2 活跃 provider 切换：状态文件指名 p2 → _providers() 把 p2 提队首；
        #     未知名/文件损坏不改变顺序；set_active_provider 原子写且返回脱敏信息
        with tempfile.TemporaryDirectory() as tmpstate:
            os.environ["LLM_ACTIVE_PROVIDER_FILE"] = str(Path(tmpstate) / "active.json")
            assert get_active_provider_name() == ""
            assert [p["name"] for p in _providers()] == ["p1", "p2"]
            got = set_active_provider("p2")
            assert got == {"name": "p2", "model": "m2"} and "api_key" not in got, got
            assert get_active_provider_name() == "p2"
            pool2 = _providers()
            assert pool2[0]["name"] == "p2" and pool2[1]["name"] == "p1", pool2
            assert set_active_provider("ghost") is None
            Path(os.environ["LLM_ACTIVE_PROVIDER_FILE"]).write_text("{broken", encoding="utf-8")
            assert get_active_provider_name() == ""
            assert [p["name"] for p in _providers()] == ["p1", "p2"]
        os.environ.pop("LLM_ACTIVE_PROVIDER_FILE", None)
        # 4. 故障转移：第一个 provider 抛异常，第二个成功（stub _post_message，不打真实 API）
        calls: List[str] = []
        def fake_post_msg(url, body, key, timeout):
            calls.append(url)
            if "http://a" in url:
                raise ConnectionError("down")
            return {"role": "assistant", "content": "p2 回复"}
        globals()["_post_message"] = fake_post_msg
        assert _call_with_failover(pool, [{"role": "user", "content": "hi"}], 5) == "p2 回复"
        assert any("http://a" in u for u in calls) and any("http://b" in u for u in calls), calls
        # 4b. 请求体带 tools/tool_choice（function calling 主路径的协议证据）
        seen_bodies: List[dict] = []
        def capture_post(url, body, key, timeout):
            seen_bodies.append(json.loads(body.decode()))
            return {"role": "assistant", "content": "ok"}
        globals()["_post_message"] = capture_post
        assert chat("u4", "随便聊聊") == "ok"
        assert seen_bodies and seen_bodies[0].get("tools") == TOOL_DEFS, seen_bodies
        assert seen_bodies[0].get("tool_choice") == "auto", seen_bodies
        # 4d. 注册表一致性：TOOL_DEFS 与系统提示都由能力注册表生成（单一来源）
        reg_names = set(capabilities.REGISTRY.names())
        assert {t["function"]["name"] for t in TOOL_DEFS} == reg_names, reg_names
        for n in reg_names:
            assert n in SYSTEM_PROMPT, f"系统提示缺能力 {n}"
        assert "禁止声称" in SYSTEM_PROMPT and "send_file" in SYSTEM_PROMPT
        # 4c. provider 不支持 tools（HTTP 400）→ 自动降级无 tools 重试成功
        def no_tools_post(url, body, key, timeout):
            payload = json.loads(body.decode())
            if "tools" in payload:
                raise urllib.error.HTTPError(url, 400, "Bad Request", {}, None)
            return {"role": "assistant", "content": "降级回复"}
        globals()["_post_message"] = no_tools_post
        assert chat("u5", "hi") == "降级回复"
        # 5. 全部 provider 失败 → None
        globals()["_post_message"] = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("down"))
        assert _call_with_failover(pool, [{"role": "user", "content": "hi"}], 5) is None
        # 6. 动作解析协议（fallback 文本协议仍可用）
        assert parse_action('{"action": "status"}') == {"action": "status"}
        assert parse_action('{"action": "exec", "command": "ls"}')["command"] == "ls"
        assert parse_action("普通文本回复") is None
        assert parse_action('{"action": broken') is None  # 不完整 JSON 按文本处理
        # 7. exec 黑名单模式：默认放行，仅拦真正危险
        with tempfile.TemporaryDirectory() as tmpwd:
            os.environ["EXEC_WORKDIR"] = tmpwd
            os.environ["TOOL_OUTPUT_DIR"] = str(Path(tmpwd) / "tool-output")
            os.environ["EXEC_AUDIT_FILE"] = str(Path(tmpwd) / "exec_audit.jsonl")
            r = execute_action({"action": "exec", "command": "echo hello"})
            assert r["ok"] and r["output"] == "hello", r
            # 7a. 默认放行：whoami 真实执行成功；id 不得被黑名单误拦
            r = execute_action({"action": "exec", "command": "whoami"})
            assert r["ok"] and r["output"], r
            r = execute_action({"action": "exec", "command": "id"})
            assert not r.get("error", "").startswith("dangerous_denied"), r
            # 7b. 危险判定（danger_reason 纯函数直测，不真跑）：
            #     rm -rf 根 / mkfs / dd of=/dev/ / 关机 / fork bomb / chmod -R 777 / / 写保护路径
            assert danger_reason("rm -rf /") == "rm_rf_protected_root"
            assert danger_reason("rm -rf /*") == "rm_rf_protected_root"
            assert danger_reason("rm -rf /etc") == "rm_rf_protected_root"
            assert danger_reason("rm -rf ~") == "rm_rf_protected_root"
            assert danger_reason("rm -rf /tmp/stale-build") is None  # 普通清理放行
            assert danger_reason("mkfs.ext4 /dev/sda1").startswith("denied_command")
            assert danger_reason("dd if=/dev/zero of=/dev/sda") == "dd_to_device"
            assert danger_reason("shutdown -h now").startswith("denied_command")
            assert danger_reason("reboot").startswith("denied_command")
            assert danger_reason("halt").startswith("denied_command")
            assert danger_reason(":(){:|:&};:") == "fork_bomb"
            assert danger_reason(":() { :|:& };:") == "fork_bomb"
            assert danger_reason("chmod -R 777 /") == "chmod_recursive_root"
            assert danger_reason("chmod -R 777 /etc") == "chmod_recursive_root"
            assert danger_reason("chmod 755 ./run.sh") is None
            assert danger_reason("echo x > /etc/passwd") == "write_protected_path"
            assert danger_reason("echo x > /root/.ssh/authorized_keys") == "write_protected_path"
            assert danger_reason("tee /etc/hosts") == "write_protected_path"
            assert danger_reason("sed -i s/a/b/ /etc/hosts") == "write_protected_path"
            assert danger_reason("cp a.txt /etc/hosts") == "write_protected_path"
            # 7b2. 重定向落盘范围：tool-output / workdir / /dev/null 放行，其他拒
            out_dir = Path(os.environ["TOOL_OUTPUT_DIR"])
            assert danger_reason(f"echo hi > {out_dir}/a.txt") is None
            assert danger_reason("echo hi > ./local.txt") is None  # 相对路径对 workdir 解析
            assert danger_reason("echo hi > /tmp/elsewhere.txt") == "write_outside_allowed_dirs"
            assert danger_reason("ps aux 2>/dev/null") is None
            # 7b3. 黑名单模式放行旧白名单外命令（判定层放行，不真执行）
            assert danger_reason("apt-get install nmap") is None
            assert danger_reason("systemctl restart sshd") is None
            assert danger_reason("docker rm abc") is None
            assert danger_reason("sudo tcpdump -i any -c 1") is None
            # 7b4. 执行层危险拒绝返回明确错误
            r = execute_action({"action": "exec", "command": "rm -rf /"})
            assert not r["ok"] and r["error"].startswith("dangerous_denied"), r
            r = execute_action({"action": "exec", "command": "shutdown -h now"})
            assert not r["ok"] and "dangerous_denied" in r["error"], r
            # 7b5. sudo 放行但记审计（执行失败也应有审计记录）
            execute_action({"action": "exec", "command": "sudo echo audit-me"})
            audit_lines = Path(os.environ["EXEC_AUDIT_FILE"]).read_text(
                encoding="utf-8").strip().splitlines()
            sudo_entries = [json.loads(l) for l in audit_lines
                            if json.loads(l).get("result") == "allowed_sudo"]
            assert any("audit-me" in e["command"] for e in sudo_entries), audit_lines
            denied_entries = [json.loads(l) for l in audit_lines
                              if json.loads(l).get("result") == "denied"]
            assert any(e.get("reason") == "rm_rf_protected_root" for e in denied_entries)
            # 7b6. cwd 固定：pwd 返回 EXEC_WORKDIR
            r = execute_action({"action": "exec", "command": "pwd"})
            assert r["ok"] and Path(r["output"]) == Path(tmpwd), r
            # 7c. ls 带 flag 不再 FileNotFoundError（subprocess 数组或原生兜底跳过 flag）
            (Path(tmpwd) / "marker.txt").write_text("x", encoding="utf-8")
            r = execute_action({"action": "exec", "command": "ls -al"})
            assert r["ok"] and "marker.txt" in r["output"], r
            r = execute_action({"action": "exec", "command": "ls -al ./"})
            assert r["ok"] and "marker.txt" in r["output"], r
            # 7d. cat 相对路径对 workdir 解析
            r = execute_action({"action": "exec", "command": "cat marker.txt"})
            assert r["ok"] and r["output"] == "x", r
            # 7e. 输出机制：≤3000 全文直出；>3000 全文落盘 + 前2000+截断标记+尾500
            short = format_tool_output("A" * 3000)
            assert short["output"] == "A" * 3000 and not short["truncated"], short
            big = "B" * 2500 + "MID" + "C" * 2000
            fmt = format_tool_output(big)
            assert fmt["truncated"] and fmt["total_chars"] == len(big), fmt
            assert fmt["output"].startswith("B" * 100), fmt["output"][:50]
            assert "[截断，共 4503 字符，全文已存" in fmt["output"], fmt["output"][1900:2200]
            assert "可发文件给你]" in fmt["output"] and fmt["output"].endswith("C" * 500)
            saved_file = Path(fmt["full_output_file"])
            assert saved_file.exists() and saved_file.read_text(encoding="utf-8") == big
            assert saved_file.parent == out_dir
            # 7e2. 真实命令超长输出（shell 路径）：截断 + 落盘一致
            big_cmd = ('"' + sys.executable + '" -c "print(\'Z\'*5000)"')
            r = execute_action({"action": "exec", "command": big_cmd})
            assert r["ok"] and r["truncated"], r
            assert "[截断" in r["output"] and Path(r["full_output_file"]).exists(), r
            # 7e3. 重定向落盘到 tool-output 真实生效（"放到文件里返回"场景）
            rf = execute_action({"action": "exec",
                                 "command": f"echo redirect-ok > {out_dir}/r.txt"})
            assert rf["ok"], rf
            assert (out_dir / "r.txt").read_text(encoding="utf-8").strip() == "redirect-ok"
        # 7e. workdir 全不可用 → 明确错误文本，拒绝执行
        globals()["exec_workdir"] = lambda: None
        r = execute_action({"action": "exec", "command": "ls"})
        assert not r["ok"] and "workdir_unavailable" in r["error"], r
        globals()["exec_workdir"] = orig_workdir
        # 8. function calling 主路径：tool_calls → 本地执行 → role:tool 回灌 → 最终回复
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["GOALS_FILE"] = str(Path(tmp) / "goals.jsonl")
            os.environ["LOOP_TASKS_FILE"] = str(Path(tmp) / "loop_tasks.jsonl")
            rounds: List[List[dict]] = []
            def tool_call_post(url, body, key, timeout):
                payload = json.loads(body.decode())
                msgs = payload["messages"]
                rounds.append(msgs)
                if not any(m.get("role") == "tool" for m in msgs):
                    assert payload.get("tools") == TOOL_DEFS  # 首轮带 tools
                    return {"role": "assistant", "content": "",
                            "tool_calls": [{"id": "call_1", "type": "function",
                                            "function": {"name": "schedule_task",
                                                         "arguments": json.dumps(
                                                             {"minutes": 5, "text": "复查目标"})}}]}
                # 第二轮：必须看到 role:tool 回灌
                tool_msg = [m for m in msgs if m.get("role") == "tool"][-1]
                assert tool_msg["tool_call_id"] == "call_1", tool_msg
                assert '"ok": true' in tool_msg["content"], tool_msg
                return {"role": "assistant", "content": "已安排，5 分钟后复查。"}
            globals()["_post_message"] = tool_call_post
            reply = chat("u9", "帮我安排个任务")
            assert reply == "已安排，5 分钟后复查。", reply
            assert len(rounds) == 2, rounds  # 确实两轮调用
            entry = json.loads((Path(tmp) / "loop_tasks.jsonl").read_text(encoding="utf-8").strip())
            assert entry["interval_min"] == 5 and entry["task"] == "复查目标", entry
            # 8b. 文本协议 fallback 两轮（provider 降级无 tools 后模型输出首行 JSON）
            rounds2: List[List[dict]] = []
            def legacy_post(url, body, key, timeout):
                payload = json.loads(body.decode())
                msgs = payload["messages"]
                rounds2.append(msgs)
                if "tools" in payload:
                    raise urllib.error.HTTPError(url, 400, "Bad Request", {}, None)
                if not any("工具执行结果" in (m.get("content") or "") for m in msgs):
                    return {"role": "assistant",
                            "content": '{"action": "schedule", "minutes": 5, "text": "复查目标"}'}
                return {"role": "assistant", "content": "已安排（fallback）。"}
            globals()["_post_message"] = legacy_post
            reply = chat("u10", "再安排一次")
            assert reply == "已安排（fallback）。", reply
            assert len(rounds2) == 2, rounds2
            # 8c. 响应完整性硬约束：首轮无 tool_calls 但含承诺词（"我去找一下/稍等"）
            #     → 自动追问一轮；追问后模型实际调工具 → 执行并返回最终结果
            rounds3: List[List[dict]] = []
            def promise_post(url, body, key, timeout):
                payload = json.loads(body.decode())
                msgs = payload["messages"]
                rounds3.append(msgs)
                followed = any(m.get("content") == PROMISE_FOLLOWUP_PROMPT for m in msgs)
                if not followed:
                    return {"role": "assistant", "content": "我去找一下文档，稍等。"}
                if not any(m.get("role") == "tool" for m in msgs):
                    return {"role": "assistant", "content": "",
                            "tool_calls": [{"id": "c_p", "type": "function",
                                            "function": {"name": "get_status",
                                                         "arguments": "{}"}}]}
                return {"role": "assistant", "content": "状态已实际查询：服务正常。"}
            globals()["_post_message"] = promise_post
            reply = chat("u12", "整理所有预期")
            assert reply == "状态已实际查询：服务正常。", reply
            # 3 轮：承诺文本 → 追问后 tool_calls → tool 回灌后最终回复
            assert len(rounds3) == 3, rounds3
            assert any(m.get("content") == PROMISE_FOLLOWUP_PROMPT for m in rounds3[1])
            assert any(m.get("role") == "tool" for m in rounds3[2])
            # 8c2. 无承诺词不追问（单轮结束）
            rounds4: List[List[dict]] = []
            def plain_post(url, body, key, timeout):
                rounds4.append(json.loads(body.decode())["messages"])
                return {"role": "assistant", "content": "今天天气不错。"}
            globals()["_post_message"] = plain_post
            assert chat("u13", "随便聊") == "今天天气不错。"
            assert len(rounds4) == 1, rounds4
            # 8c3. 承诺词表扩充：新形态命中；完成式回答（已为你统计如下）不误判
            for p in ("让我统计文件总数并分块列出", "让我看看目录结构", "我看一下配置",
                      "我先确认一下状态", "我来分析这个日志", "我来查一下文档",
                      "我帮你统计文件数", "先查一下服务状态", "容我确认",
                      "让我获取更清晰的目录结构概览。", "让我跑一下扫描"):
                assert PROMISE_RE.search(p), p
            for np_ in ("已为你统计如下：共 3 个文档", "文档列表如下：a.md、b.md",
                        "统计结果：共 5 个文件", "今天天气不错。",
                        "这让我想到之前的配置", "你让我觉得这个方案可行"):
                assert not PROMISE_RE.search(np_), np_
            # 8c4. 最终轮兜住：第一轮调了工具，第二轮收尾文本含承诺词且无
            #      后续 tool_calls → 追加一轮追问，不再悬空结束
            rounds5: List[List[dict]] = []
            def tool_then_promise_post(url, body, key, timeout):
                payload = json.loads(body.decode())
                msgs = payload["messages"]
                rounds5.append(msgs)
                if any(m.get("content") == PROMISE_FOLLOWUP_PROMPT for m in msgs):
                    return {"role": "assistant", "content": "统计完成：共 3 个文档。"}
                if not any(m.get("role") == "tool" for m in msgs):
                    return {"role": "assistant", "content": "",
                            "tool_calls": [{"id": "c_tp", "type": "function",
                                            "function": {"name": "get_status",
                                                         "arguments": "{}"}}]}
                return {"role": "assistant", "content": "让我统计一下文件总数。"}
            globals()["_post_message"] = tool_then_promise_post
            reply = chat("u15", "统计 docs 里的文档")
            assert reply == "统计完成：共 3 个文档。", reply
            # 3 轮：tool_calls → tool 回灌后承诺文本 → 追问后最终回复
            assert len(rounds5) == 3, rounds5
            assert any(m.get("content") == PROMISE_FOLLOWUP_PROMPT for m in rounds5[2])
            # 8c5. 最终轮正常回答不追问（工具轮后直接收尾，无承诺词 → 不追加轮次）
            rounds6: List[List[dict]] = []
            def tool_then_plain_post(url, body, key, timeout):
                msgs = json.loads(body.decode())["messages"]
                rounds6.append(msgs)
                if not any(m.get("role") == "tool" for m in msgs):
                    return {"role": "assistant", "content": "",
                            "tool_calls": [{"id": "c_tq", "type": "function",
                                            "function": {"name": "get_status",
                                                         "arguments": "{}"}}]}
                return {"role": "assistant", "content": "已为你统计如下：共 2 个文档。"}
            globals()["_post_message"] = tool_then_plain_post
            reply = chat("u16", "统计一下")
            assert reply == "已为你统计如下：共 2 个文档。", reply
            assert len(rounds6) == 2, rounds6
            # 8c6. 工具轮次耗尽兜底：模型每轮都要调工具 → MAX_TOOL_ROUNDS 用尽后
            #      强制无 tools 收尾总结，不把中间叙事/未执行 tool_calls 悬空返回
            rounds7: List[dict] = []
            def always_tool_post(url, body, key, timeout):
                payload = json.loads(body.decode())
                rounds7.append(payload)
                if "tools" not in payload:
                    # 兜底收尾调用：确认指令要求直接总结
                    assert any("工具调用轮次已达上限" in (m.get("content") or "")
                               for m in payload["messages"]), payload["messages"][-1]
                    return {"role": "assistant",
                            "content": "基于已收集结果：docs 共 3 个文档。"}
                return {"role": "assistant", "content": "让我继续获取。",
                        "tool_calls": [{"id": "c_x", "type": "function",
                                        "function": {"name": "get_status",
                                                     "arguments": "{}"}}]}
            globals()["_post_message"] = always_tool_post
            reply = chat("u17", "穷尽工具轮")
            assert reply == "基于已收集结果：docs 共 3 个文档。", reply
            tool_rounds = [p for p in rounds7 if "tools" in p]
            closing_rounds = [p for p in rounds7 if "tools" not in p]
            assert len(tool_rounds) == MAX_TOOL_ROUNDS + 1, len(tool_rounds)  # 首轮+6轮
            assert len(closing_rounds) == 1, len(closing_rounds)
            # 8d. send_file 工具：chat_id/file_sender 由消费进程注入的上下文提供
            fpath = Path(tmp) / "result.txt"
            fpath.write_text("扫描结果", encoding="utf-8")
            sent: List[tuple] = []
            set_chat_context("u14", chat_id="oc_14",
                             file_sender=lambda cid, p: sent.append((cid, p)) or Path(p).name,
                             source="test")
            def sendfile_post(url, body, key, timeout):
                msgs = json.loads(body.decode())["messages"]
                if not any(m.get("role") == "tool" for m in msgs):
                    return {"role": "assistant", "content": "",
                            "tool_calls": [{"id": "c_f", "type": "function",
                                            "function": {"name": "send_file",
                                                         "arguments": json.dumps(
                                                             {"path": str(fpath)})}}]}
                return {"role": "assistant", "content": "文件已发你。"}
            globals()["_post_message"] = sendfile_post
            reply = chat("u14", "把结果文件发我")
            assert reply == "文件已发你。", reply
            assert sent == [("oc_14", str(fpath))], sent
            _contexts.pop("u14", None)
            # 8d2. send_file 无注入上下文 → 结构化错误（模型须转述，禁止编"没有接口"）
            r = execute_tool("send_file", {"path": str(fpath)}, None)
            assert not r["ok"] and r["error"] == "file_channel_unavailable", r
        # 9. 历史裁剪与 TTL（直接注入内存验证，不依赖网络）
        _histories["u2"] = [{"role": "user", "content": str(i)}
                            for i in range(HISTORY_LIMIT + 5)]  # 必超上限才验裁剪(与值无关)
        _last_active["u2"] = time.time()
        _prune("u2")
        assert len(_histories["u2"]) == HISTORY_LIMIT
        _last_active["u3"] = time.time() - HISTORY_TTL_SEC - 1
        _histories["u3"] = [{"role": "user", "content": "x"}]
        _prune("u2")
        assert "u3" not in _histories and "u3" not in _last_active
    finally:
        globals()["_post_message"] = orig_post_msg
        globals()["exec_workdir"] = orig_workdir
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
    print("model_client self-test ok (function-calling/failover/fallback/workdir paths, no real API call)")
    return 0


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit("用法: python core/model_client.py --self-test")
