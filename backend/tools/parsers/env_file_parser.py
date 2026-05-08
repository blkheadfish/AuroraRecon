"""
env_file_parser.py
Parse ``.env``-style files (dotenv, Laravel, Rails, Symfony, Django-environ,
Docker Compose ``.env``, Node ``.env.production`` …).

Security focus:
  - Detect credentials (DB_PASSWORD, JWT_SECRET, APP_KEY, AWS_*, …).
  - Pull out connection URLs (DATABASE_URL, REDIS_URL, MONGO_URL).
  - Identify framework flavor via signature keys.
  - Return masked summaries for prompts; full (raw) map is kept in facts
    so fact_sink can record credentials to ``state.confirmed_facts['creds']``.

Also applied to ``web.config``, ``database.yml``, ``application.properties``
etc. through the dispatcher fallback (key=value line matching is surprisingly
robust for all of these).
"""
from __future__ import annotations

import re
from typing import Any

_LINE_RE = re.compile(
    r"""^\s*
        (?P<key>[A-Z_][A-Z0-9_.\-]{0,80})
        \s*=\s*
        (?P<val>
            "(?:\\.|[^"\\])*"      # double-quoted
          | '(?:\\.|[^'\\])*'      # single-quoted
          | [^\r\n
        )
        \s*(?:\
    """,
    re.VERBOSE | re.MULTILINE,
)


_SENSITIVE_KEYS_RE = re.compile(
    r"^(?:"
    r"(?:DB|DATABASE|MYSQL|POSTGRES|POSTGRESQL|PG|MONGO|MONGODB|REDIS|MEMCACHED|"
    r"ELASTIC|ELASTICSEARCH|RABBITMQ|AMQP|KAFKA|CASSANDRA|"
    r"MAIL|SMTP|SENDGRID|MAILGUN|MAILTRAP)_(?:PASSWORD|PWD|SECRET|KEY|DSN|URL)"
    r"|APP_KEY|APP_SECRET|APP_SECRET_KEY|SECRET_KEY|SECRET_KEY_BASE"
    r"|JWT_SECRET|JWT_KEY|SESSION_SECRET|COOKIE_SECRET"
    r"|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN"
    r"|AZURE_.*(?:KEY|SECRET|CONNECTION_STRING)"
    r"|GCP_.*(?:KEY|SECRET)"
    r"|GITHUB_TOKEN|GITLAB_TOKEN|DOCKER_PASSWORD|NPM_TOKEN"
    r"|STRIPE_.*KEY|TWILIO_.*(?:TOKEN|SECRET)|SENTRY_AUTH_TOKEN"
    r"|CSRF_TOKEN|ENCRYPTION_KEY|PRIVATE_KEY|SIGNING_KEY"
    r")$",
    re.IGNORECASE,
)


_URL_CREDS_RE = re.compile(
    r"(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ftp|ssh)"
    r"://(?P<user>[^:@/\s]+):(?P<pwd>[^@/\s]+)@",
    re.IGNORECASE,
)


_FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "laravel":   ["APP_KEY", "APP_ENV", "DB_CONNECTION", "BROADCAST_DRIVER"],
    "rails":     ["SECRET_KEY_BASE", "RAILS_ENV", "RAILS_MASTER_KEY"],
    "symfony":   ["APP_SECRET", "DATABASE_URL", "SYMFONY_DECRYPTION_SECRET"],
    "django":    ["DJANGO_SECRET_KEY", "DJANGO_SETTINGS_MODULE", "DJANGO_DEBUG"],
    "flask":     ["FLASK_APP", "FLASK_ENV", "FLASK_SECRET_KEY"],
    "express":   ["NODE_ENV", "EXPRESS_SESSION_SECRET", "PORT"],
    "nestjs":    ["NEST_ENV", "NODE_ENV"],
    "nextjs":    ["NEXT_PUBLIC_API_URL", "NEXTAUTH_SECRET", "NEXTAUTH_URL"],
    "spring":    ["SPRING_PROFILES_ACTIVE", "SPRING_DATASOURCE_URL"],
}


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    return raw


def is_env_file_content(text: str, path: str = "") -> bool:
    if not text:
        return False
    lp = (path or "").lower()
    if lp.endswith(".env") or ".env." in lp or lp.endswith("dotenv"):
        return True
    lines = text.splitlines()[:40]
    kv_lines = sum(1 for ln in lines if _LINE_RE.match(ln))
    total = sum(1 for ln in lines if ln.strip() and not ln.lstrip().startswith("#"))
    return total >= 3 and kv_lines / max(total, 1) >= 0.6


def parse_env_file(text: str) -> dict[str, Any]:
    if not text:
        return {}

    entries: dict[str, str] = {}
    for m in _LINE_RE.finditer(text):
        key = m.group("key").strip()
        val = _unquote(m.group("val"))
        entries[key] = val

    sensitive: list[dict[str, str]] = []
    url_creds: list[dict[str, str]] = []
    for key, val in entries.items():
        if _SENSITIVE_KEYS_RE.search(key):
            sensitive.append({"key": key, "value": val})
        for um in _URL_CREDS_RE.finditer(val):
            url_creds.append({
                "key": key,
                "user": um.group("user"),
                "password": um.group("pwd"),
                "raw": val[:200],
            })

    frameworks: list[str] = []
    upper_keys = {k.upper() for k in entries}
    for name, sigs in _FRAMEWORK_SIGNATURES.items():
        if any(sig.upper() in upper_keys for sig in sigs):
            frameworks.append(name)

    facts: dict[str, Any] = {
        "entry_count": len(entries),
        "keys": sorted(entries.keys()),
    }
    if sensitive:
        facts["sensitive"] = sensitive
    if url_creds:
        facts["url_credentials"] = url_creds
    if frameworks:
        facts["frameworks"] = sorted(frameworks)

    debug_flag = entries.get("APP_DEBUG") or entries.get("DEBUG") or entries.get("DJANGO_DEBUG")
    if debug_flag and debug_flag.strip().lower() in ("true", "1", "on", "yes"):
        facts["debug_enabled"] = True

    env_flag = (entries.get("APP_ENV") or entries.get("NODE_ENV") or
                entries.get("RAILS_ENV") or entries.get("FLASK_ENV") or "")
    if env_flag:
        facts["deployment_env"] = env_flag.strip().lower()

    return facts


def derive_attack_surface(facts: dict[str, Any]) -> dict[str, Any]:
    surface: dict[str, Any] = {}
    if facts.get("sensitive") or facts.get("url_credentials"):
        surface["credential_leak"] = True
        surface["credential_count"] = (
            len(facts.get("sensitive", [])) + len(facts.get("url_credentials", []))
        )
    if facts.get("debug_enabled"):
        surface["debug_mode"] = True
        surface["debug_risk"] = "生产环境开启 debug，错误回显泄露代码/路径"
    if facts.get("frameworks"):
        surface["frameworks"] = facts["frameworks"]
    env_name = (facts.get("deployment_env") or "").lower()
    if env_name in ("production", "prod", "live") and surface.get("credential_leak"):
        surface["prod_credential_leak"] = True
    return surface


def _mask(value: str) -> str:
    if not value:
        return "***"
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "…" + value[-2:]


def summarise_for_context(facts: dict[str, Any], max_chars: int = 600) -> str:
    if not facts:
        return ""
    lines = ["配置文件 (.env) 摘要:"]
    if facts.get("frameworks"):
        lines.append(f"- 识别框架: {', '.join(facts['frameworks'])}")
    if facts.get("deployment_env"):
        lines.append(f"- 部署环境: {facts['deployment_env']}")
    if facts.get("debug_enabled"):
        lines.append("- ⚠ DEBUG 模式开启")
    sens = facts.get("sensitive") or []
    if sens:
        masked = [f"{e['key']}={_mask(e['value'])}" for e in sens[:5]]
        lines.append(f"- 敏感键 ({len(sens)}): {', '.join(masked)}")
    url_creds = facts.get("url_credentials") or []
    if url_creds:
        c0 = url_creds[0]
        lines.append(
            f"- URL 凭据 ({len(url_creds)}): {c0.get('key', '?')} "
            f"user={c0.get('user', '?')} pwd={_mask(c0.get('password', ''))}"
        )
    return "\n".join(lines)[:max_chars]
