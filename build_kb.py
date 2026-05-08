#!/usr/bin/env python3
"""
知识库构建入口

用法:
    python build_kb.py

    python build_kb.py -v fastjson_1224

    python build_kb.py -l

    python build_kb.py --add-url my_vuln "My Vuln Name" "https://example.com/readme.md"

前置条件:
    export LLM_API_KEY=
    export LLM_MODEL=deepseek-v4-flash
    export LLM_BASE_URL=https://api.deepseek.com
    export KB_EMBEDDING_BASE_URL="https://api.jina.ai/v1"
    export KB_EMBEDDING_API_KEY="jina_7ff181acac1a459f94d538150bace722YDofDfTsvyr66aePvsnZVT6zKC6R"
    export KB_EMBEDDING_MODEL="jina-embeddings-v3"
"""
from backend.knowledge.builder import main

if __name__ == "__main__":
    main()
