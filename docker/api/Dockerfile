# ===================================================
# PentestAI API 服务镜像
# 包含 Docker CLI（用于启动工具沙箱容器）
# ===================================================
FROM python:3.11-slim

WORKDIR /app

# 安装 Docker CLI（静态二进制，不依赖 apt 源）
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && DOCKER_VERSION="27.3.1" \
    && curl -fsSL "https://mirrors.aliyun.com/docker-ce/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" \
       -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz --strip-components=1 -C /usr/local/bin/ docker/docker \
    && rm /tmp/docker.tgz \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN pip install --no-deps PyJWT bcrypt

# 复制项目代码
COPY . .

# 确保所有 Python 包可导入
RUN touch backend/__init__.py \
    backend/agents/__init__.py \
    backend/tools/__init__.py \
    backend/tools/parsers/__init__.py \
    backend/llm/__init__.py \
    backend/llm/prompts/__init__.py \
    backend/report/__init__.py \
    backend/api/__init__.py \
    backend/db/__init__.py \
    backend/storage/__init__.py

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

#CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]