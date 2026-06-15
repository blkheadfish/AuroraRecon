const KNOWN_COLORS: Record<string, string> = {
  java_deserialization: '#c9a04e',
  config_exploit: '#6bb56e',
  weak_credential: '#c97d7d',
  sql_injection: '#b370c9',
  ssti: '#c9825e',
  expression_injection: '#9b7ab8',
  file_upload: '#5a9e99',
  command_injection: '#c9726e',
  ctf_challenge: '#5e9ad0',
}

const PALETTE: string[] = [
  '#6baed4',
  '#6bbf8b',
  '#c4a658',
  '#c98070',
  '#9b8ec4',
  '#68b8b0',
  '#c080b0',
  '#8cbf78',
  '#889eb8',
  '#bfa870',
  '#90a8c0',
  '#78b898',
]

function normalizeCategory(category: unknown): string {
  const raw = String(category || '').trim().toLowerCase()
  return raw || 'uncategorized'
}

function hashString(input: string): number {
  let hash = 0
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0
  }
  return Math.abs(hash)
}

export function resolveCategoryColor(category: unknown): string {
  const normalized = normalizeCategory(category)
  if (KNOWN_COLORS[normalized]) return KNOWN_COLORS[normalized]
  const idx = hashString(normalized) % PALETTE.length
  return PALETTE[idx]
}

export { KNOWN_COLORS }
