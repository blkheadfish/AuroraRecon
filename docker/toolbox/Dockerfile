# ===================================================
# pentest-toolbox —— 预装所有安全工具的工具箱镜像
# 构建：docker build -t pentest-toolbox:latest .
#
# 扩展工具（不改 Dockerfile 时）：起临时容器 → 安装 → 提交回同一标签
#   docker run -d --name toolbox_upgrade_tmp pentest-toolbox:latest sleep 3600
#   docker exec -it toolbox_upgrade_tmp bash   # apt install / go build 等
#   docker commit toolbox_upgrade_tmp pentest-toolbox:latest && docker rm -f toolbox_upgrade_tmp
# 项目内示例脚本：docker/toolbox/fix.sh（安装 phuip-fpizdam 后 commit）
# ===================================================
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/bin:/root/.local/bin:${PATH}"

# ---------- 镜像源（阿里云主 + 清华备，先 HTTP 引导）----------
RUN echo "deb http://mirrors.aliyun.com/kali kali-rolling main non-free contrib" \
    > /etc/apt/sources.list \
    && echo "deb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main non-free contrib" \
    >> /etc/apt/sources.list

# ---------- 引导阶段：装基础包 + GPG 公钥 + 切 HTTPS ----------
RUN apt-get update --allow-insecure-repositories 2>/dev/null || true \
    && apt-get install -y --allow-unauthenticated \
       gnupg2 curl ca-certificates unzip \
    && curl -fsSL https://archive.kali.org/archive-key.asc \
       | gpg --batch --yes --dearmor \
       > /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg \
    && echo "deb https://mirrors.aliyun.com/kali kali-rolling main non-free contrib" \
       > /etc/apt/sources.list \
    && echo "deb https://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main non-free contrib" \
       >> /etc/apt/sources.list \
    && apt-get update

# ---------- 系统基础工具 ----------
RUN apt-get install -y --no-install-recommends \
    wget git vim unzip \
    python3 python3-pip python3-venv \
    build-essential gcc make \
    iputils-ping net-tools dnsutils netcat-openbsd iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ---------- 渗透测试工具 ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan hping3 \
    nikto gobuster dirb whatweb wafw00f sslscan \
    sqlmap \
    hydra medusa john \
    hashcat \
    enum4linux smbclient ldap-utils onesixtyone \
    tcpdump tshark socat \
    wordlists \
    && rm -rf /var/lib/apt/lists/*

# ---------- Java JDK（JNDI 利用需要 javac）----------
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk \
    && rm -rf /var/lib/apt/lists/*

# ---------- JNDI 利用工具 ----------
RUN mkdir -p /opt/jndi && cd /opt/jndi \
    && (curl -fsSL --retry 3 --max-time 120 \
        "https://github.com/Mr-xn/JNDIExploit-1/releases/download/v1.2/JNDIExploit.v1.2.zip" \
        -o /tmp/jndi.zip \
    || curl -fsSL --retry 3 --max-time 120 \
        "https://github.com/Mr-xn/JNDIExploit-1/releases/download/v1.2/JNDIExploit.v1.2.zip" \
        -o /tmp/jndi.zip) \
    && unzip -o /tmp/jndi.zip -d /opt/jndi/ \
    && rm -f /tmp/jndi.zip \
    && echo "JNDIExploit installed" \
    || echo "WARN: JNDIExploit download failed"

# ysoserial（Java 反序列化 payload 生成器）
RUN (curl -fsSL --retry 3 --max-time 120 \
        "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
        -o /opt/ysoserial.jar \
    || curl -fsSL --retry 3 --max-time 120 \
        "https://ghfast.top/https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
        -o /opt/ysoserial.jar) \
    && echo "ysoserial installed" \
    || echo "WARN: ysoserial download failed"

# JNDI 一键利用脚本 + BCEL 无回连利用脚本
COPY jndi_fastjson.sh /opt/jndi_fastjson.sh
COPY bcel_fastjson.py /opt/bcel_fastjson.py
COPY shiro_exploit.py /opt/shiro_exploit.py
COPY shiro_webshell_brute.sh /opt/shiro_webshell_brute.sh
RUN chmod +x /opt/jndi_fastjson.sh /opt/bcel_fastjson.py /opt/shiro_exploit.py /opt/shiro_webshell_brute.sh

# ---------- Metasploit（包较大，加重试）----------
RUN apt-get update \
    && for i in 1 2 3; do \
        apt-get install -y --no-install-recommends --fix-missing \
            metasploit-framework \
        && break \
        || { echo "Retry $i..."; apt-get update --fix-missing; sleep 5; }; \
    done \
    && rm -rf /var/lib/apt/lists/*

# ---------- Nuclei 二进制 ----------
RUN NUCLEI_VER="3.3.8" \
    && (curl -fsSL --retry 3 --max-time 120 \
       "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
       -o /tmp/nuclei.zip \
    || curl -fsSL --retry 3 --max-time 120 \
       "https://ghfast.top/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
       -o /tmp/nuclei.zip) \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    || echo "WARN: nuclei install failed"

# ---------- subfinder ----------
RUN (curl -fsSL --retry 3 --max-time 60 \
    "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip" \
    -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm -f /tmp/subfinder.zip) || echo "WARN: subfinder install failed"

# ---------- httpx ----------
RUN (curl -fsSL --retry 3 --max-time 60 \
    "https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip" \
    -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm -f /tmp/httpx.zip) || echo "WARN: httpx install failed"

# ---------- ffuf ----------
RUN (curl -fsSL --retry 3 --max-time 60 \
    "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" \
    -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm -f /tmp/ffuf.tar.gz) || echo "WARN: ffuf install failed"

# ---------- Nuclei 更新模板 ----------
RUN nuclei -update-templates -silent \
    || git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
    || echo "WARN: nuclei templates failed"

# ---------- Python 工具（用阿里云 PyPI 镜像）----------
RUN pip3 install -i https://mirrors.aliyun.com/pypi/simple/ \
    --no-cache-dir --break-system-packages dnsrecon || true
RUN pip3 install -i https://mirrors.aliyun.com/pypi/simple/ \
    --no-cache-dir --break-system-packages arjun || true
RUN pip3 install --no-cache-dir --break-system-packages \
    git+https://github.com/devanshbatham/paramspider || true

# ---------- 创建精简版 rockyou 字典 ----------
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        zcat /usr/share/wordlists/rockyou.txt.gz | head -100 \
        > /usr/share/wordlists/rockyou-top100.txt; \
        gunzip /usr/share/wordlists/rockyou.txt.gz || true; \
    else \
        printf 'admin\npassword\n123456\nroot\ntoor\ntest\nguest\n1234\nadmin123\nletmein\n' \
        > /usr/share/wordlists/rockyou-top100.txt; \
    fi

# ── 安装 JDK 8（专给 ysoserial）──────────────────────────
# Kali/Debian 系：
RUN apt-get update && \
    apt-get install -y --no-install-recommends openjdk-8-jdk-headless && \
    rm -rf /var/lib/apt/lists/*

# 如果 apt 里没有 openjdk-8（某些新版 Kali），用 Adoptium Temurin：
# RUN mkdir -p /usr/lib/jvm/java-8 && \
#     curl -sL "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u422-b05/OpenJDK8U-jdk_x64_linux_hotspot_8u422b05.tar.gz" \
#     | tar xz --strip-components=1 -C /usr/lib/jvm/java-8

ENV JAVA8=/usr/lib/jvm/java-8/bin/java

# 验证两个 JDK 共存
RUN ${JAVA8} -version 2>&1 | head -1 && java -version 2>&1 | head -1

WORKDIR /workspace
CMD ["/bin/bash"]