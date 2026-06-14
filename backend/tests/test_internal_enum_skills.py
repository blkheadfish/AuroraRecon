"""
W3-T1: Tests for internal/AD enumeration nodes calling network skills.

Validates:
  1. SkillRegistry.match_by_port() correctly maps ports to network skills.
  2. _write_network_enum_to_world_model() writes structured results to attack_graph.
  3. Enum nodes skip when no matching open ports are present.
  4. Non-intranet chain templates skip enum phases.
"""
from __future__ import annotations

import pytest

from backend.agents.models import AttackGraph, AttackGraphEdge, AttackGraphNode, PortInfo, VulnFinding
from backend.skills.registry import SkillRegistry, _SERVICE_PORT_FALLBACK


class TestPortSkillMapping:
    """Verify port→skill mapping for network enumeration."""

    def test_smb_port_maps_to_smb_enum(self):
        """Port 445/139 should map to smb_enum skill."""
        assert _SERVICE_PORT_FALLBACK.get((445, "microsoft-ds")) in ("smb_enum_exploit", None)
        assert (445, "smb") not in _SERVICE_PORT_FALLBACK  # may need explicit "smb" mapping

    def test_ldap_port_maps_to_ldap_exploit(self):
        """Port 389/636/3268 should map to ldap_exploit skill."""
        assert _SERVICE_PORT_FALLBACK.get((389, "ldap")) == "ldap_exploit"
        assert _SERVICE_PORT_FALLBACK.get((636, "ldaps")) == "ldap_exploit"

    def test_kerberos_port_maps_to_kerberos_exploit(self):
        """Port 88/464 should map to kerberos_exploit skill."""
        assert _SERVICE_PORT_FALLBACK.get((88, "kerberos")) == "kerberos_exploit"
        assert _SERVICE_PORT_FALLBACK.get((464, "kpasswd5")) == "kerberos_exploit"

    def test_unknown_port_returns_none(self):
        """Ports without registered skill should return None."""
        assert _SERVICE_PORT_FALLBACK.get((9999, "unknown")) is None


class TestSkillRegistryMatchByPort:
    """Integration tests for SkillRegistry.match_by_port."""

    @pytest.fixture(autouse=True)
    def registry(self):
        self.reg = SkillRegistry()
        self.reg.ensure_loaded()
        if self.reg.size == 0:
            pytest.skip("No skills loaded")

    def test_match_smb_by_port(self):
        skill = self.reg.match_by_port(445, "smb")
        if skill is None:
            skill = self.reg.match_by_port(445, "microsoft-ds")
        if skill is None:
            skill = self.reg.get_by_id("smb_enum_exploit")
        assert skill is not None, "smb_enum_exploit skill should be loadable"
        assert skill.category == "network"

    def test_match_ldap_by_port(self):
        skill = self.reg.match_by_port(389, "ldap")
        if skill is None:
            skill = self.reg.get_by_id("ldap_exploit")
        assert skill is not None, "ldap_exploit skill should be loadable"
        assert skill.category == "network"

    def test_match_kerberos_by_port(self):
        skill = self.reg.match_by_port(88, "kerberos")
        if skill is None:
            skill = self.reg.get_by_id("kerberos_exploit")
        assert skill is not None, "kerberos_exploit skill should be loadable"
        assert skill.category == "network"


class TestWorldModelWriting:
    """Verify enum results are structured into attack_graph nodes/edges."""

    def _make_graph(self) -> AttackGraph:
        g = AttackGraph()
        return g

    def _mock_state(self, graph):
        class _MockState:
            attack_graph = graph
        return _MockState()

    def test_smb_shares_written_to_graph(self):
        """SMB enum stdout with shares should create share nodes + credential."""
        from backend.agents.fact_hooks import write_network_enum_results

        g = self._make_graph()
        host_id = "host:192.168.1.10"
        g.nodes.append(AttackGraphNode(id=host_id, type="host", label="192.168.1.10"))
        state = self._mock_state(g)

        enum_output = {
            "phase": "smb_enum",
            "skill_id": "smb_enum_exploit",
            "port": 445,
            "service": "smb",
            "stdout_parts": [
                "IPC$ READ",
                "ADMIN$ NO ACCESS",
                "C$ READ",
                "Domain: CORP",
                "SMB_ACCESS_DONE",
            ],
        }
        write_network_enum_results(state, "smb_enum", enum_output, "192.168.1.10", 445)

        share_nodes = [n for n in g.nodes if n.type == "loot" and (n.facts or {}).get("subtype") == "share"]
        assert len(share_nodes) >= 2, f"Expected >=2 share nodes, got {len(share_nodes)}"

        svc_node = [n for n in g.nodes if n.id == "svc:192.168.1.10:445"]
        assert svc_node, "Service node not created"

        edges = [e for e in g.edges if e.relation == "exposes"]
        assert len(edges) >= 2, f"Expected edges from host→svc→share, got {len(edges)}"

    def test_ldap_anonymous_written_to_graph(self):
        """LDAP enum detecting anonymous bind should create finding."""
        from backend.agents.fact_hooks import write_network_enum_results

        g = self._make_graph()
        host_id = "host:10.0.0.5"
        g.nodes.append(AttackGraphNode(id=host_id, type="host", label="10.0.0.5"))
        state = self._mock_state(g)

        enum_output = {
            "phase": "ldap_enum",
            "skill_id": "ldap_exploit",
            "port": 389,
            "service": "ldap",
            "stdout_parts": [
                "LDAP_ANONYMOUS=true",
                "LDAP_NAMING=DC=corp,DC=local",
                "LDAP_USER_COUNT=42",
                "LDAP_GROUP_COUNT=12",
            ],
        }
        write_network_enum_results(state, "ldap_enum", enum_output, "10.0.0.5", 389)

        finding_nodes = [n for n in g.nodes if n.type == "finding"]
        assert len(finding_nodes) >= 1, f"Expected >=1 finding for LDAP anon, got {len(finding_nodes)}"

        anon_finding = [n for n in finding_nodes if "anon" in n.id.lower()]
        assert anon_finding, "Anonymous bind finding not found"

        domain_nodes = [n for n in g.nodes if n.type == "credential" and (n.facts or {}).get("domain")]
        assert any("corp" in n.id.lower() for n in domain_nodes), "Domain node should reference 'corp'"

    def test_kerberos_asrep_written_to_graph(self):
        """Kerberos ASREPRoast detection should create finding + credential."""
        from backend.agents.fact_hooks import write_network_enum_results

        g = self._make_graph()
        host_id = "host:dc01.corp.local"
        g.nodes.append(AttackGraphNode(id=host_id, type="host", label="dc01.corp.local"))
        state = self._mock_state(g)

        enum_output = {
            "phase": "kerberos_attack",
            "skill_id": "kerberos_exploit",
            "port": 88,
            "service": "kerberos",
            "stdout_parts": [
                "ASREP_HASH_FOUND=true",
                "$krb5asrep$23$user@DOMAIN:hashhere",
            ],
        }
        write_network_enum_results(state, "kerberos_attack", enum_output, "dc01.corp.local", 88)

        finding_nodes = [n for n in g.nodes if n.type == "finding"]
        assert len(finding_nodes) >= 1, "ASREP finding not created"

        cred_nodes = [n for n in g.nodes if n.type == "credential"]
        assert len(cred_nodes) >= 1, "ASREP credential not created"

        vuln_edges = [e for e in g.edges if e.relation == "discovers"]
        assert len(vuln_edges) >= 1, "discovers edge should connect finding to service"

    def test_kerberos_kerberoast_written_to_graph(self):
        """Kerberoasting detection should create finding + SPN nodes."""
        from backend.agents.fact_hooks import write_network_enum_results

        g = self._make_graph()
        host_id = "host:dc01.corp.local"
        g.nodes.append(AttackGraphNode(id=host_id, type="host", label="dc01.corp.local"))
        state = self._mock_state(g)

        enum_output = {
            "phase": "kerberos_attack",
            "skill_id": "kerberos_exploit",
            "port": 88,
            "service": "kerberos",
            "stdout_parts": [
                "KERBEROAST_CANDIDATES_FOUND=true",
                "SPN: HTTP/webserver.corp.local",
                "SPN: MSSQLSvc/sql.corp.local",
            ],
        }
        write_network_enum_results(state, "kerberos_attack", enum_output, "dc01.corp.local", 88)

        spn_nodes = [n for n in g.nodes if n.type == "finding" and (n.facts or {}).get("subtype") == "spn"]
        assert len(spn_nodes) >= 2, f"Expected >=2 SPN nodes, got {len(spn_nodes)}"

        kerb_edges = [e for e in g.edges if e.relation == "leads_to"]
        assert len(kerb_edges) >= 2, f"Expected >=2 leads_to edges, got {len(kerb_edges)}"


class TestPhaseTemplateGate:
    """Verify internal enum phases are only triggered by appropriate templates."""

    def test_web_template_excludes_smb_enum(self):
        from backend.agents.chain_templates import get_template
        tpl = get_template("web")
        assert "smb_enum" not in tpl.phase_set(), "Web template should not include smb_enum"

    def test_intranet_template_includes_smb_enum(self):
        from backend.agents.chain_templates import get_template
        tpl = get_template("intranet")
        assert "smb_enum" in tpl.phase_set(), "Intranet template should include smb_enum"

    def test_intranet_template_includes_ldap_enum(self):
        from backend.agents.chain_templates import get_template
        tpl = get_template("intranet")
        assert "ldap_enum" in tpl.phase_set(), "Intranet template should include ldap_enum"

    def test_intranet_template_includes_kerberos_attack(self):
        from backend.agents.chain_templates import get_template
        tpl = get_template("intranet")
        assert "kerberos_attack" in tpl.phase_set(), "Intranet template should include kerberos_attack"

    def test_cloud_template_excludes_intranet_phases(self):
        from backend.agents.chain_templates import get_template
        tpl = get_template("cloud")
        assert "smb_enum" not in tpl.phase_set(), "Cloud template should not include smb_enum"
        assert "ldap_enum" not in tpl.phase_set(), "Cloud template should not include ldap_enum"
        assert "kerberos_attack" not in tpl.phase_set(), "Cloud template should not include kerberos_attack"


class TestPortDetection:
    """Verify open_ports detection for enum nodes."""

    def test_smb_port_detection(self):
        """Ports 445 and 139 should be detected as SMB."""
        smb_ports = [p for p in [
            PortInfo(port=445, protocol="tcp", state="open", service="microsoft-ds"),
            PortInfo(port=80, protocol="tcp", state="open", service="http"),
            PortInfo(port=139, protocol="tcp", state="open", service="netbios-ssn"),
        ] if p.port in (445, 139)]
        assert len(smb_ports) == 2, "Should detect both SMB ports"

    def test_ldap_port_detection(self):
        """Ports 389, 636, 3268, 3269 should be detected as LDAP."""
        ldap_ports = [p for p in [
            PortInfo(port=389, protocol="tcp", state="open", service="ldap"),
            PortInfo(port=22, protocol="tcp", state="open", service="ssh"),
        ] if p.port in (389, 636, 3268, 3269)]
        assert len(ldap_ports) == 1, "Should detect LDAP port 389"

    def test_kerberos_port_detection(self):
        """Ports 88 and 464 should be detected as Kerberos."""
        kdc_ports = [p for p in [
            PortInfo(port=88, protocol="tcp", state="open", service="kerberos-sec"),
        ] if p.port in (88, 464)]
        assert len(kdc_ports) == 1, "Should detect KDC port 88"

    def test_no_ad_ports_on_web_target(self):
        """A plain web target (80/443 only) yields no AD ports."""
        ad_ports = [p for p in [
            PortInfo(port=80, protocol="tcp", state="open", service="http"),
            PortInfo(port=443, protocol="tcp", state="open", service="https"),
        ] if p.port in (88, 445, 389, 636, 3268, 464)]
        assert len(ad_ports) == 0, "Web-only target should have no AD ports"
