/**
 * 工具链 / 命令气泡的工具名展示统一入口 (协议 v2)。
 *
 * 后端 push_decision 时已计算 ``display_tool``, Redis Stream envelope 中的
 * ``decision_event.payload.display_tool`` 直接可用。此处仅做防御层处理:
 *   - 优先 ``display_tool``
 *   - 其次非 shell 的 ``tool``
 *   - 再从命令首段推断
 *   - 兜底返回 ``script``
 *
 * SHELL_NAMES 集合保留用于处理旧任务 / 直接注入的边界情况。
 */

const SHELL_NAMES: ReadonlySet<string> = new Set([
  '/bin/bash',
  '/bin/sh',
  'bash',
  'sh',
  '/bin/zsh',
  'zsh',
])

const SKIP_PREFIX_RE =
  /^(set\s|export\s|cd\s|echo\s|#|if\s|then\b|else\b|fi\b|do\b|done\b|while\s|for\s|\[)/
const VAR_ASSIGN_RE = /^\w+=/

export function isShellTool(name?: string | null): boolean {
  if (!name) return false
  return SHELL_NAMES.has(String(name))
}

/** 从 shell 命令/脚本里挑第一段非控制流非赋值的 token 当工具名. */
export function inferToolFromCommand(cmd?: string | null): string {
  if (!cmd) return ''
  for (const seg of String(cmd).split(/[;\n|]|&&|\|\|/)) {
    const trimmed = seg.trim()
    if (!trimmed) continue
    if (SKIP_PREFIX_RE.test(trimmed)) continue
    if (VAR_ASSIGN_RE.test(trimmed)) continue
    const token = trimmed.split(/\s/)[0]
    const name = token.split('/').pop() || ''
    if (name && !SHELL_NAMES.has(name)) return name
  }
  return ''
}

export interface ToolDisplaySource {
  display_tool?: string | null
  tool?: string | null
  command?: string | null
  purpose?: string | null
}

/**
 * 解析单条 decision_event / 工具调用记录的展示工具名。
 * @returns 永远不会返回空串或 shell 名。
 */
export function resolveToolDisplay(entry: ToolDisplaySource | null | undefined): string {
  const e = entry || {}
  const display = (e.display_tool || '').trim()
  if (display && !SHELL_NAMES.has(display)) return display

  const tool = (e.tool || '').trim()
  if (tool && !SHELL_NAMES.has(tool)) return tool

  const fromCmd = inferToolFromCommand(e.command || '')
  if (fromCmd) return fromCmd

  const purpose = (e.purpose || '').trim()
  if (purpose) {
    // purpose 通常是 ``deep_scan_admin`` / ``verify_lfi`` 这种 ``<动作>_<细节>``,
    // 取第一段就够当工具语义,避免暴露过多上下文。
    return purpose.split('_')[0] || 'script'
  }
  return 'script'
}
