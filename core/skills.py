"""Skill packs: modular ``SKILL.md`` dispatchers loaded on demand.

Layout (mirrors the user's existing CTF skill)::

    .codebuddy/skills/<pack>/SKILL.md          # dispatcher: when to use, module index
    .codebuddy/skills/<pack>/modules/*.md      # depth, loaded lazily

A :class:`~core.modes.Mode` names a pack; :func:`compose_prompt` folds the
dispatcher (plus any requested modules) into the turn's system prompt, capped so
a runaway pack cannot blow the context window.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

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


# -- first-turn module floor -------------------------------------------------
#
# The system prompt carries only the dispatcher; depth is pulled on demand with the
# ``read_knowledge`` tool. That is the main path. This is the *floor*: the first turn
# of a hunt has no recon yet, so the operator's own sentence is the only signal —
# matching the obvious words saves a round trip. Deliberately blunt (substring match,
# no model call) and deliberately capped: guessing wide here just burns the budget
# that on-demand pulling exists to protect.

_MODULE_SIGNALS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("android", "apk", "安卓", "客户端", "hybrid", "webview", "jsbridge", "小程序",
      "intent", "导出组件"), "mobile"),
    (("域名", "白名单", "allowlist", "跳转", "redirect", "重定向"), "url-trust"),
    (("idor", "越权", "水平权限", "垂直权限"), "idor"),
    (("ssrf",), "ssrf"),
    (("注入", "sqli", "sql", "命令执行", "rce", "ssti", "模板注入"), "injection"),
    (("登录", "认证", "会话", "token", "jwt", "oauth", "单点"), "auth"),
    (("组合链", "利用链", "提权", "接管", "串联"), "chains"),
    (("侦察", "信息收集", "资产", "子域", "子域名", "端点", "攻击面"), "recon"),
)

# Report discipline applies to every hunt, so it is never conditional.
FLOOR_ALWAYS: Tuple[str, ...] = ("evidence",)
FLOOR_DEFAULT: Tuple[str, ...] = ("recon",)
FLOOR_MAX_MATCHED = 2


def select_modules(text: str, root: Path | str = SKILLS_ROOT, pack: str = "pentest") -> List[str]:
    """Module names to inject for the first turn, given the operator's sentence.

    Pure and cheap: substring match over ``_MODULE_SIGNALS``, capped at
    ``FLOOR_MAX_MATCHED`` distinct hits, plus the always-on floor. Falls back to
    ``FLOOR_DEFAULT`` when nothing matches, because "进站建面" is the default posture.
    Names that the pack does not actually ship are dropped, so this can never inject
    a module that does not exist.
    """
    available = set(module_names(pack, root))
    lowered = (text or "").lower()

    matched: List[str] = []
    for needles, module in _MODULE_SIGNALS:
        if module in matched or module in FLOOR_ALWAYS:
            continue
        if any(needle in lowered for needle in needles):
            matched.append(module)
        if len(matched) >= FLOOR_MAX_MATCHED:
            break

    chosen = list(FLOOR_ALWAYS) + (matched or list(FLOOR_DEFAULT))
    return [name for name in dict.fromkeys(chosen) if name in available]


__all__ = ["SkillModule", "SkillPack", "discover", "load", "compose_prompt",
           "module_names", "select_modules", "SKILLS_ROOT", "DEFAULT_MAX_CHARS",
           "FLOOR_ALWAYS", "FLOOR_DEFAULT"]
