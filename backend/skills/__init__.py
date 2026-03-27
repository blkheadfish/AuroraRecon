"""
skills/ —— Exploit Skill 系统

原理驱动的漏洞利用框架：
  Skill ≠ "某道CTF题的答案"
  Skill = "某类漏洞的完整利用方法论，可适配不同环境"

架构：
  models.py    数据模型
  loader.py    YAML 加载 + 校验
  registry.py  匹配检索
  engine.py    执行引擎（探测 → 选路径 → 按步执行 → LLM兜底）
"""
