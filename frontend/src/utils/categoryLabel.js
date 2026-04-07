const CATEGORY_LABELS = {
  recon: '侦察',
  vuln_scan: '漏洞扫描',
  exploit: '漏洞利用',
  post_exploit: '后渗透',
  post: '后渗透',
  general: '通用',
  web: 'Web',
  network: '网络',
  osint: '情报',
  ctf_challenge: 'CTF 靶场',

  java_deserialization: 'Java 反序列化',
  config_exploit: '配置利用',
  weak_credential: '弱口令',
  sql_injection: 'SQL 注入',
  ssti: '模板注入',
  expression_injection: '表达式注入',
  file_upload: '文件上传',
  command_injection: '命令注入',

  uncategorized: '未分类',
}

function normalizeCategory(category) {
  const raw = String(category || '').trim().toLowerCase()
  return raw || 'uncategorized'
}

export function resolveCategoryLabel(category) {
  const normalized = normalizeCategory(category)
  return CATEGORY_LABELS[normalized] || String(category || '未分类')
}

export { CATEGORY_LABELS }
