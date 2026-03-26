#!/usr/bin/env python3
"""
知识库构建入口

用法:
    # 构建全部（约20个漏洞，耗时3-5分钟）
    python build_kb.py

    # 只构建某个漏洞
    python build_kb.py -v fastjson_1224

    # 查看已构建状态
    python build_kb.py -l

    # 临时添加一个自定义数据源并构建
    python build_kb.py --add-url my_vuln "My Vuln Name" "https://example.com/readme.md"

前置条件:
    export LLM_API_KEY=
    export LLM_MODEL=deepseek-chat          # 可选，默认deepseek-chat
    export LLM_BASE_URL=https://api.deepseek.com  # 可选
    # 可选
    export KB_EMBEDDING_BASE_URL="https://api.jina.ai/v1"
    export KB_EMBEDDING_API_KEY="jina_7ff181acac1a459f94d538150bace722YDofDfTsvyr66aePvsnZVT6zKC6R"
    export KB_EMBEDDING_MODEL="jina-embeddings-v3"
"""
from backend.knowledge.builder import main

if __name__ == "__main__":
    main()
