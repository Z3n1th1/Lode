"""Skill packs: modular ``SKILL.md`` dispatchers loaded on demand.

Layout (mirrors the user's existing CTF skill)::

    .codebuddy/skills/<pack>/SKILL.md          # dispatcher: when to use, module index
    .codebuddy/skills/<pack>/modules/*.md      # depth, loaded lazily

A :class:`~core.modes.Mode` names a pack; :func:`compose_prompt` folds the
dispatcher (plus any requested modules) into the turn's system prompt, capped so
a runaway pack cannot blow the context window.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

SKILLS_ROOT = Path(__file__).resolve().parents[1] / ".codebuddy" / "skills"
DEFAULT_MAX_CHARS = 24_000


@dataclass(frozen=True)
class SkillModule:
    name: str
    path: Path
    description: str = ""


@dataclass(frozen=True)
class SkillPack:
    name: str
    root: Path
    entry: Path
    modules: Tuple[SkillModule, ...] = field(default_factory=tuple)


def _frontmatter(text: str) -> Dict[str, str]:
    """Minimal ``key: value`` frontmatter parser (no YAML dependency)."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    out: Dict[str, str] = {}
    for line in text[3:end].split("\n"):
        if ":" in line and not line.strip().startswith("#"):
            key, _, value = line.partition(":")
            out[key.strip().lower()] = value.strip().strip('"').strip("'")
    return out


def _module_description(path: Path) -> str:
    try:
        head = path.read_text(encoding="utf-8")[:400]
    except OSError:
        return ""
    return _frontmatter(head).get("description", "")


def discover(root: Path | str = SKILLS_ROOT) -> Dict[str, SkillPack]:
    """Every pack with a readable ``SKILL.md`` under ``root``."""
    base = Path(root)
    packs: Dict[str, SkillPack] = {}
    if not base.is_dir():
        return packs
    for child in sorted(base.iterdir()):
        entry = child / "SKILL.md"
        if not child.is_dir() or not entry.is_file():
            continue
        modules: List[SkillModule] = []
        modules_dir = child / "modules"
        if modules_dir.is_dir():
            for md in sorted(modules_dir.glob("*.md")):
                modules.append(SkillModule(name=md.stem, path=md, description=_module_description(md)))
        packs[child.name] = SkillPack(name=child.name, root=child, entry=entry, modules=tuple(modules))
    return packs


def load(name: str, root: Path | str = SKILLS_ROOT) -> Optional[SkillPack]:
    return discover(root).get(str(name or "").strip())


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def compose_prompt(name: str, *, modules: Sequence[str] = (), max_chars: int = DEFAULT_MAX_CHARS,
                   root: Path | str = SKILLS_ROOT) -> str:
    """Dispatcher text (+ requested modules), or "" when the pack is missing.

    Missing packs are not an error: the caller simply gets the default prompt.
    """
    pack = load(name, root)
    if pack is None:
        return ""
    parts = [_read(pack.entry).strip()]
    wanted = [str(m).strip() for m in modules if str(m).strip()]
    if wanted:
        by_name = {m.name: m for m in pack.modules}
        for module_name in wanted:
            module = by_name.get(module_name)
            if module is not None:
                parts.append(_read(module.path).strip())
    text = "\n\n".join(p for p in parts if p)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n[... skill pack truncated ...]"
    return text


def module_names(name: str, root: Path | str = SKILLS_ROOT) -> List[str]:
    pack = load(name, root)
    return [m.name for m in pack.modules] if pack else []


# -- knowledge retrieval -----------------------------------------------------
#
# Pull-only. Nothing here is injected unless somebody asks for it by name, which is
# what lets the library grow without the prompt growing with it. Two tiers resolve
# through the same call:
#
#   module:<pack>  .codebuddy/skills/<pack>/modules/<name>.md   distilled patterns
#   kb             references/knowledge-base/<name>.md          long-form cards
#
# Both entry points share this: the conversation turn (via the read_knowledge tool in
# agents/src_chat.py) and the background hunt (via activation in agents/src_agent.py).

KNOWLEDGE_CHAR_LIMIT = 12_000
_KNOWLEDGE_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def knowledge_roots(root: Path | str = SKILLS_ROOT) -> List[Tuple[str, Path]]:
    """``(label, dir)`` for every place a knowledge file may live, in pull order."""
    base = Path(root)
    roots: List[Tuple[str, Path]] = []
    for name, pack in sorted(discover(base).items()):
        roots.append((f"module:{name}", pack.root / "modules"))
    roots.append(("kb", base.parents[1] / "references" / "knowledge-base"))
    return roots


def knowledge_catalogue(root: Path | str = SKILLS_ROOT) -> List[str]:
    """Every pullable name. Returned on a miss so a caller can correct itself."""
    names: List[str] = []
    for _label, directory in knowledge_roots(root):
        try:
            names.extend(p.stem for p in directory.glob("*.md") if p.name != "README.md")
        except OSError:
            continue
    return sorted(set(names))


def read_knowledge(name: str, *, limit: int = KNOWLEDGE_CHAR_LIMIT,
                   root: Path | str = SKILLS_ROOT) -> Dict[str, Any]:
    """One knowledge file by bare name, bounded.

    Returns ``{"name", "source", "chars", "truncated", "text"}`` on a hit and
    ``{"error", "name", "available"}`` on a miss. A name that is not a bare
    ``[A-Za-z0-9_-]`` stem is refused, so this can never become an arbitrary file
    reader. Truncation is explicit — a silent cut would look like the file ended.
    """
    stem = str(name or "").strip().removesuffix(".md")
    if not _KNOWLEDGE_NAME_RE.fullmatch(stem):
        return {"error": "invalid name", "name": stem,
                "hint": "bare filename stem, e.g. mobile"}
    for label, directory in knowledge_roots(root):
        path = directory / f"{stem}.md"
        try:
            if not path.is_file() or path.is_symlink():
                continue
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        truncated = len(text) > limit
        if truncated:
            text = text[:limit] + "\n\n[... truncated — this file is longer than one pull ...]"
        return {"name": stem, "source": label, "chars": len(text),
                "truncated": truncated, "text": text}
    return {"error": "not found", "name": stem, "available": knowledge_catalogue(root)}


# -- first-turn module floor -------------------------------------------------
#
# The system prompt carries only the dispatcher; depth is pulled on demand with the
# ``read_knowledge`` tool. That is the main path. This is the *floor*: the first turn
# of a hunt has no recon yet, so the operator's own sentence is the only signal —
# matching the obvious words saves a round trip. Deliberately blunt (substring match,
# no model call) and deliberately capped: guessing wide here just burns the budget
# that on-demand pulling exists to protect.

_MODULE_SIGNALS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("android", "apk", "安卓", "hybrid", "webview", "jsbridge", "小程序",
      "导出组件", "exported", "content provider", "deep link"), "mobile"),
    (("域名", "白名单", "allowlist", "ends with", "endswith", "host 校验",
      "beta-", "staging-", "跳转", "redirect"), "url-trust"),
    (("idor", "越权", "水平权限", "垂直权限", "user_id", "org_id", "order_id"), "idor"),
    (("ssrf", "服务端请求伪造", "内网", "169.254.169.254"), "ssrf"),
    (("注入", "sqli", "sql syntax", "sqlstate", "ora-", "pg_query", "mysql_fetch",
      "unclosed quotation", "命令执行", "rce", "ssti", "模板注入",
      "排序参数", "order_by", "orderbycolumn"), "injection"),
    (("jwt", "oauth", "认证", "单点", "重置密码", "改绑"), "auth"),
    (("组合链", "利用链", "提权", "接管", "串联"), "chains"),
    (("侦察", "信息收集", "子域", "子域名", "攻击面", "端点", "源站", "孤儿"), "recon"),
)
# 故意收窄:这个词表同时用于"跑到中途遇到信号就激活",而激活的卡片会在**后续每一轮**
# 都进 system prompt。所以精确比召回重要 —— `token` / `session` / `metadata` 这类词在
# 任何现代 API 响应里都出现,拿它们当触发条件等于每轮都激活错的东西、白烧预算,还把
# 真正相关的那篇挤掉。宁可漏(模型可以自己点名要),不要误激活。

# Report discipline applies to every hunt, so it is never conditional.
FLOOR_ALWAYS: Tuple[str, ...] = ("evidence",)
FLOOR_DEFAULT: Tuple[str, ...] = ("recon",)
FLOOR_MAX_MATCHED = 2


def signal_modules(text: str, *, limit: int = 3, root: Path | str = SKILLS_ROOT,
                   pack: str = "pentest") -> List[str]:
    """Which patterns a piece of text signals, by substring match. Pure and cheap.

    Deliberately blunt — it is a *trigger*, not a classifier. Used twice: to pick the
    first-turn floor from the operator's sentence, and to activate a playbook mid-hunt
    when a response or a hypothesis shows the matching shape. Names the pack does not
    actually ship are dropped, so neither caller can inject a module that does not exist.
    """
    available = set(module_names(pack, root))
    lowered = (text or "").lower()
    matched: List[str] = []
    for needles, module in _MODULE_SIGNALS:
        if module in matched or module in FLOOR_ALWAYS:
            continue
        if any(needle in lowered for needle in needles):
            matched.append(module)
        if len(matched) >= limit:
            break
    return [name for name in matched if name in available]


def select_modules(text: str, root: Path | str = SKILLS_ROOT, pack: str = "pentest") -> List[str]:
    """Module names to inject for the first turn, given the operator's sentence.

    The always-on floor plus ``signal_modules``, capped at ``FLOOR_MAX_MATCHED``, and
    falling back to ``FLOOR_DEFAULT`` because "进站建面" is the default posture. This is
    only the floor: depth is activated on demand.
    """
    chosen = list(FLOOR_ALWAYS) + (
        signal_modules(text, limit=FLOOR_MAX_MATCHED, root=root, pack=pack) or list(FLOOR_DEFAULT)
    )
    available = set(module_names(pack, root))
    return [name for name in dict.fromkeys(chosen) if name in available]


__all__ = ["SkillModule", "SkillPack", "discover", "load", "compose_prompt",
           "module_names", "select_modules", "signal_modules", "read_knowledge",
           "knowledge_roots", "knowledge_catalogue", "SKILLS_ROOT",
           "DEFAULT_MAX_CHARS", "KNOWLEDGE_CHAR_LIMIT",
           "FLOOR_ALWAYS", "FLOOR_DEFAULT", "FLOOR_MAX_MATCHED"]
