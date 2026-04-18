"""Regression tests for the phpinfo extraction hook inside ``node_intel_harvest``."""
from __future__ import annotations

from backend.agents.models import PentestState, PortInfo
from backend.agents.fact_hooks import apply_phpinfo_extraction as _apply_phpinfo_extraction


PHPINFO_BODY_RFI = """
<html><body>
<h1>PHP Version 7.4.3</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">doc_root</td><td class="v">/var/www/html/antibot_image/antibots</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td></tr>
<tr><td class="e">disable_functions</td><td class="v">no value</td></tr>
</table>
</body></html>
"""

PHPINFO_BODY_LOCKED = """
<html><body>
<h1>PHP Version 7.4.3</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">disable_functions</td><td class="v">system,exec,passthru,shell_exec,popen,proc_open</td></tr>
<tr><td class="e">open_basedir</td><td class="v">/var/www/html</td></tr>
</table>
</body></html>
"""


def _state() -> PentestState:
    state = PentestState(target="http://test.local")
    state.open_ports.append(PortInfo(port=80, protocol="tcp", service="http"))
    return state


def test_phpinfo_extraction_writes_state():
    state = _state()
    harvested = [{
        "type": "page",
        "path": "/antibots/info.php",
        "body": PHPINFO_BODY_RFI,
        "code": "200",
        "headers": "",
    }]
    _apply_phpinfo_extraction(state, harvested, "http://test.local:80", 80)
    assert state.php_runtime.get("allow_url_include") is True
    assert state.php_runtime.get("doc_root") == "/var/www/html/antibot_image/antibots"
    surface = state.php_runtime.get("_attack_surface") or {}
    assert surface.get("rfi_possible") is True


def test_phpinfo_extraction_creates_rfi_finding():
    state = _state()
    harvested = [{
        "type": "page",
        "path": "/info.php",
        "body": PHPINFO_BODY_RFI,
        "code": "200",
        "headers": "",
    }]
    _apply_phpinfo_extraction(state, harvested, "http://test.local:80", 80)
    rfi_findings = [f for f in state.findings if "allow_url_include=On" in f.name]
    assert len(rfi_findings) == 1
    assert rfi_findings[0].severity == "high"
    assert rfi_findings[0].exploitable is True


def test_phpinfo_extraction_locked_env_no_finding():
    state = _state()
    harvested = [{
        "type": "page",
        "path": "/phpinfo.php",
        "body": PHPINFO_BODY_LOCKED,
        "code": "200",
        "headers": "",
    }]
    _apply_phpinfo_extraction(state, harvested, "http://test.local:80", 80)
    assert state.php_runtime.get("allow_url_include") is False
    surface = state.php_runtime.get("_attack_surface") or {}
    assert surface.get("shell_cmd_restricted") is True
    assert not any("allow_url_include=On" in f.name for f in state.findings)


def test_phpinfo_ignores_non_php_pages():
    state = _state()
    harvested = [{
        "type": "page",
        "path": "/index.html",
        "body": "<h1>Welcome to nginx!</h1>",
        "code": "200",
        "headers": "",
    }]
    _apply_phpinfo_extraction(state, harvested, "http://test.local:80", 80)
    assert state.php_runtime == {}
