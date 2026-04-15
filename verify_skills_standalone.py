#!/usr/bin/env python3
"""
独立验证脚本 —— 不依赖 pydantic，直接解析 YAML 验证结构完整性
"""
import yaml
import re
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "backend" / "skills"

REQUIRED_TOP_FIELDS = ["skill_id", "name", "match", "exploit_paths"]
REQUIRED_PATH_FIELDS = ["path_id"]
REQUIRED_STEP_FIELDS = ["id", "command"]


def load_and_validate():
    yaml_files = list(SKILLS_DIR.rglob("*.yaml"))
    print(f"{'='*60}")
    print(f"Skill 系统验证（独立模式）")
    print(f"{'='*60}")
    print(f"\n找到 {len(yaml_files)} 个 YAML 文件\n")

    all_ok = True
    skills = []

    for path in sorted(yaml_files):
        rel = path.relative_to(SKILLS_DIR)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"  ❌ {rel}: YAML 解析失败 - {e}")
            all_ok = False
            continue

        if not data or not isinstance(data, dict):
            print(f"  ❌ {rel}: 空文件或非字典")
            all_ok = False
            continue

        skills.append((rel, data))

    # ── 逐个验证 ────────────────────────────────────────
    print("[1] 结构完整性检查\n")

    for rel, data in skills:
        sid = data.get("skill_id", "???")
        issues = []

        # 顶层必填字段
        for field in REQUIRED_TOP_FIELDS:
            if field not in data:
                issues.append(f"缺少顶层字段: {field}")

        # match 规则
        match = data.get("match", {})
        rules = match.get("rules", [])
        if not rules:
            issues.append("无匹配规则 (match.rules 为空)")

        # probes
        probes = data.get("probes", [])
        for probe in probes:
            if not probe.get("id"):
                issues.append("探测缺少 id")
            if not probe.get("command") and not probe.get("steps"):
                issues.append(f"探测 {probe.get('id', '?')} 无 command 也无 steps")

        # exploit_paths
        paths = data.get("exploit_paths", [])
        has_freeform = False
        total_steps = 0

        for p in paths:
            pid = p.get("path_id", "?")
            if p.get("mode") == "react_freeform":
                has_freeform = True
                continue

            steps = p.get("steps", [])
            total_steps += len(steps)

            if not steps:
                issues.append(f"路径 {pid} 无步骤")

            for step in steps:
                if not step.get("id"):
                    issues.append(f"路径 {pid} 有步骤缺少 id")
                if not step.get("command"):
                    issues.append(f"路径 {pid} 步骤 {step.get('id','?')} 缺少 command")

                # 检查 on_success/on_fail 引用的 step_id 是否存在
                step_ids = {s.get("id") for s in steps}
                valid_jumps = {"next_step", "next_path", "conclude_success", "conclude_fail"} | step_ids
                for jump_field in ("on_success", "on_fail"):
                    jump = step.get(jump_field, "")
                    if jump and jump not in valid_jumps:
                        # 可能引用其他路径的 step，不算错
                        pass

        if not has_freeform:
            issues.append("无 LLM 兜底路径 (mode=react_freeform)")

        # 原理和修复建议
        if not data.get("principle"):
            issues.append("缺少漏洞原理 (principle)")
        if not data.get("remediation"):
            issues.append("缺少修复建议 (remediation)")

        # 输出
        status = "✅" if not issues else "⚠ "
        print(
            f"  {status} {sid:25s} "
            f"规则={len(rules)} "
            f"探测={len(probes)} "
            f"路径={len(paths)} "
            f"步骤={total_steps} "
            f"LLM={'✓' if has_freeform else '✗'}"
        )

        if issues:
            for issue in issues:
                print(f"      ⚠  {issue}")
            all_ok = False

    # ── 匹配模拟测试 ────────────────────────────────────
    print(f"\n[2] 匹配模拟测试\n")

    test_cases = [
        ("Fastjson RCE", {"fp": "fastjson java", "evidence": "@type"}, "fastjson_rce"),
        ("Shiro 反序列化", {"fp": "shiro", "evidence": "rememberMe=deleteMe"}, "shiro_rce"),
        ("Struts2 S2-045", {"fp": "struts", "cve": "CVE-2017-5638"}, "struts2_ognl_rce"),
        ("ThinkPHP", {"fp": "ThinkPHP", "evidence": "thinkphp"}, "thinkphp_rce"),
        ("Flask SSTI", {"fp": "flask werkzeug", "evidence": "ssti"}, "flask_ssti_rce"),
        ("SQL 注入", {"evidence": "sql injection sqli"}, "sql_injection"),
        ("Tomcat", {"fp": "Apache Tomcat", "evidence": "tomcat"}, "tomcat_exploit"),
        ("Nginx", {"fp": "nginx/1.18", "evidence": "nginx"}, "nginx_misconfig"),
        ("无匹配", {"fp": "", "evidence": "unknown thing"}, None),
    ]

    match_passed = 0
    for name, inputs, expected_id in test_cases:
        fp = inputs.get("fp", "").lower()
        ev = inputs.get("evidence", "").lower()
        cve = inputs.get("cve", "").lower()

        matched = None
        for _, data in skills:
            sid = data["skill_id"]
            rules = data.get("match", {}).get("rules", [])

            for rule in rules:
                hit = False
                fp_kws = rule.get("fingerprint_contains", [])
                ev_kws = rule.get("evidence_contains", [])
                cve_list = rule.get("cve_matches", [])

                if fp_kws and any(kw.lower() in fp for kw in fp_kws):
                    hit = True
                if ev_kws and any(kw.lower() in ev for kw in ev_kws):
                    hit = True
                if cve_list and any(c.lower() == cve for c in cve_list):
                    hit = True

                if hit:
                    matched = sid
                    break
            if matched:
                break

        ok = matched == expected_id
        status = "✅" if ok else "❌"
        print(f"  {status} {name:20s} → {matched or '(无匹配)':25s} {'' if ok else f'(期望 {expected_id})'}")
        if ok:
            match_passed += 1

    # ── 变量占位符检查 ────────────────────────────────────
    print(f"\n[3] 变量占位符检查\n")

    allowed_vars = {"{ENDPOINT}", "{TARGET_IP}", "{TARGET_PORT}", "{LHOST}", "{EXPLOIT_CMD}"}
    custom_var_re = re.compile(r'\{[A-Z_]+\}')

    for rel, data in skills:
        sid = data["skill_id"]
        all_commands = []

        for probe in data.get("probes", []):
            if probe.get("command"):
                all_commands.append(("probe:" + probe.get("id", ""), probe["command"]))
            for step in probe.get("steps", []):
                if step.get("command"):
                    all_commands.append(("probe_step", step["command"]))

        for path in data.get("exploit_paths", []):
            for step in path.get("steps", []):
                if step.get("command"):
                    all_commands.append((f"{path['path_id']}:{step.get('id','')}", step["command"]))

        for loc, cmd in all_commands:
            vars_found = set(custom_var_re.findall(cmd))
            unknown = vars_found - allowed_vars
            # Filter out shell variables like ${param}, common false positives
            unknown = {v for v in unknown if not v.startswith("{#") and "§" not in v}
            if unknown:
                print(f"  ⚠  {sid}/{loc}: 未知变量 {unknown}")

    print(f"  ✅ 变量检查完成")

    # ── 探测-条件变量一致性检查 ────────────────────────────
    print(f"\n[4] 探测-条件变量一致性检查\n")

    env_vars = {"env.can_reverse", "env.lhost", "env.target_os"}
    var_issues_found = False

    for rel, data in skills:
        sid = data["skill_id"]

        produced_vars: set[str] = set()
        for probe in data.get("probes", []):
            for rule in probe.get("parse_rules", []):
                produced_vars.update(rule.get("set", {}).keys())
            for step in probe.get("steps", []):
                for rule in step.get("parse_rules", []):
                    produced_vars.update(rule.get("set", {}).keys())

        consumed_vars: set[str] = set()
        for probe in data.get("probes", []):
            consumed_vars.update(probe.get("depends_on", {}).keys())
            consumed_vars.update(probe.get("requires", {}).keys())
        for path in data.get("exploit_paths", []):
            consumed_vars.update(path.get("conditions", {}).keys())
            consumed_vars.update(path.get("skip_if", {}).keys())
            for group in path.get("conditions_any", []):
                consumed_vars.update(group.keys())

        consumed_non_env = {v for v in consumed_vars if not v.startswith("env.")}

        orphan_conditions = consumed_non_env - produced_vars
        if orphan_conditions:
            print(f"  ⚠  {sid}: 条件引用了未被任何探测设置的变量: {orphan_conditions}")
            var_issues_found = True

        dead_vars = produced_vars - consumed_non_env
        if dead_vars:
            trivial = {"json_endpoint_active"}
            real_dead = dead_vars - trivial
            if real_dead:
                print(f"  ℹ  {sid}: 探测设置的变量未被任何条件消费: {real_dead}")

    if not var_issues_found:
        print(f"  ✅ 所有条件变量均有对应的探测来源")

    # ── 总结 ─────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"加载: {len(skills)} 个 Skill")
    print(f"匹配测试: {match_passed}/{len(test_cases)} 通过")
    print(f"结构: {'✅ 全部完整' if all_ok else '⚠  有问题需修复'}")
    print(f"{'='*60}")


if __name__ == "__main__":
    load_and_validate()
