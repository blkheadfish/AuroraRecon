"""Regression tests for ``phpinfo_parser``."""
from __future__ import annotations

from backend.tools.parsers.phpinfo_parser import (
    derive_attack_surface,
    is_phpinfo_content,
    parse_phpinfo,
    summarise_for_context,
)


HTML_SAMPLE = """<!DOCTYPE html>
<html><body>
<h1 class="p">PHP Version 7.4.3-4ubuntu2.19</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux antibot 5.4.0-74-generic</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">doc_root</td><td class="v">/var/www/html/antibot_image/antibots</td><td class="v">no value</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">disable_functions</td><td class="v">no value</td><td class="v">no value</td></tr>
<tr><td class="e">open_basedir</td><td class="v">no value</td><td class="v">no value</td></tr>
<tr><td class="e">session.save_path</td><td class="v">/var/lib/php/sessions</td></tr>
<tr><td class="e">upload_tmp_dir</td><td class="v">/tmp</td></tr>
</table>
<h2>openssl</h2>
<h2>curl</h2>
<h2>mysqli</h2>
<h2>Configuration</h2>
</body></html>
"""

PLAIN_SAMPLE = """phpinfo()
PHP Version => 7.4.33

System => Linux antibot 5.4.0
Server API => Command Line Interface
doc_root => /var/www/html
allow_url_include => Off => Off
allow_url_fopen => On => On
disable_functions => system,exec,passthru,shell_exec,popen,proc_open => same
open_basedir => /var/www/html => same
session.save_path => /var/lib/php/sessions => /var/lib/php/sessions

[PHP Modules]
curl
mysqli
openssl
[Zend Modules]
"""


def test_is_phpinfo_detection():
    assert is_phpinfo_content(HTML_SAMPLE)
    assert is_phpinfo_content(PLAIN_SAMPLE)
    assert not is_phpinfo_content("<h1>Welcome to nginx!</h1>")


def test_parse_html_phpinfo():
    facts = parse_phpinfo(HTML_SAMPLE)
    assert facts.get("php_version") == "7.4.3-4ubuntu2.19"
    assert facts.get("sapi") == "Apache 2.0 Handler"
    assert facts.get("doc_root") == "/var/www/html/antibot_image/antibots"
    assert facts.get("allow_url_include") is True
    assert facts.get("allow_url_fopen") is True
    assert facts.get("disable_functions") == []
    assert facts.get("session_save_path") == "/var/lib/php/sessions"
    ext = facts.get("loaded_extensions") or []
    assert "openssl" in [e.lower() for e in ext]
    assert "curl" in [e.lower() for e in ext]


def test_parse_plain_phpinfo():
    facts = parse_phpinfo(PLAIN_SAMPLE)
    assert facts.get("php_version") == "7.4.33"
    assert facts.get("allow_url_include") is False
    assert facts.get("allow_url_fopen") is True
    df = facts.get("disable_functions")
    assert isinstance(df, list)
    for fn in ("system", "exec", "passthru", "shell_exec", "popen", "proc_open"):
        assert fn in df, f"expected {fn} in disable_functions"
    assert facts.get("open_basedir") == "/var/www/html"


def test_derive_attack_surface_allow_url_include():
    facts = parse_phpinfo(HTML_SAMPLE)
    surface = derive_attack_surface(facts)
    assert surface.get("rfi_possible") is True
    assert surface.get("url_fopen") is True
    assert surface.get("shell_cmd_restricted") is False


def test_derive_attack_surface_shell_restricted():
    facts = parse_phpinfo(PLAIN_SAMPLE)
    surface = derive_attack_surface(facts)
    assert surface.get("shell_cmd_restricted") is True
    assert set(surface.get("disabled_cmd_functions", [])) == {
        "system", "exec", "passthru", "shell_exec", "popen", "proc_open",
    }
    assert surface.get("open_basedir_restricted") is True


def test_summarise_is_truncated():
    facts = parse_phpinfo(HTML_SAMPLE)
    s = summarise_for_context(facts, max_chars=160)
    assert s
    assert len(s) <= 160
    assert "PHP Version" in s
