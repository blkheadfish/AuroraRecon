const KNOWN_COLORS = {
  java_deserialization: '#e6a23c',
  config_exploit: '#67c23a',
  weak_credential: '#f56c6c',
  sql_injection: '#e040fb',
  ssti: '#ff7043',
  expression_injection: '#ab47bc',
  file_upload: '#26a69a',
  command_injection: '#ef5350',
  ctf_challenge: '#42a5f5',
}

const PALETTE = [
  '#4ec9b8',
  '#58c79d',
  '#5aaee9',
  '#ae8cf2',
  '#8ea5be',
  '#f39c6b',
  '#56c6ff',
  '#7ed07f',
  '#ff6f91',
  '#b39ddb',
  '#ffd166',
  '#55d6c2',
]

function normalizeCategory(category) {
  const raw = String(category || '').trim().toLowerCase()
  return raw || 'uncategorized'
}

function hashString(input) {
  let hash = 0
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0
  }
  return Math.abs(hash)
}

export function resolveCategoryColor(category) {
  const normalized = normalizeCategory(category)
  if (KNOWN_COLORS[normalized]) return KNOWN_COLORS[normalized]
  const idx = hashString(normalized) % PALETTE.length
  return PALETTE[idx]
}

export { KNOWN_COLORS }
