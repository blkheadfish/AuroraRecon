import { computed, toValue, type MaybeRefOrGetter } from 'vue'

export type PathFilter = 'all' | 'high' | 's200' | 's403'

export interface PathEntry {
  path: string
  status: number
  confidence: number
  highValue: boolean
  badge?: string
  hints?: string[]
}

export interface PathNode {
  key: string
  label: string
  fullPath: string
  isLeaf: boolean
  status?: number
  confidence?: number
  highValue: boolean
  selfHighValue: boolean
  badge?: string
  hints?: string[]
  children?: PathNode[]
}

function splitSegments(p: string): string[] {
  const trimmed = p.replace(/^\/+/, '').replace(/\/+$/, '')
  if (!trimmed) return []
  return trimmed.split('/').filter(Boolean)
}

function buildTree(entries: PathEntry[]): PathNode[] {
  const root: PathNode = {
    key: '/',
    label: '/',
    fullPath: '/',
    isLeaf: false,
    highValue: false,
    selfHighValue: false,
    children: [],
  }

  const indexByKey = new Map<string, PathNode>()
  indexByKey.set('/', root)

  for (const entry of entries) {
    const segments = splitSegments(entry.path)
    if (segments.length === 0) {
      root.isLeaf = true
      root.status = entry.status
      root.confidence = entry.confidence
      root.selfHighValue = entry.highValue
      if (entry.highValue) root.highValue = true
      root.badge = entry.badge
      root.hints = entry.hints
      continue
    }

    let parent = root
    let prefix = ''
    segments.forEach((seg, idx) => {
      prefix += '/' + seg
      const isLast = idx === segments.length - 1
      let node = indexByKey.get(prefix)
      if (!node) {
        node = {
          key: prefix,
          label: seg,
          fullPath: prefix,
          isLeaf: false,
          highValue: false,
          selfHighValue: false,
          children: [],
        }
        indexByKey.set(prefix, node)
        parent.children!.push(node)
      }
      if (isLast) {
        node.isLeaf = true
        node.status = entry.status
        node.confidence = entry.confidence
        node.selfHighValue = entry.highValue
        node.badge = entry.badge
        node.hints = entry.hints
      }
      parent = node
    })
  }

  // Propagate highValue up from leaves to ancestors; sort children.
  const finalize = (node: PathNode): boolean => {
    let anyHV = node.selfHighValue
    if (node.children && node.children.length) {
      for (const child of node.children) {
        if (finalize(child)) anyHV = true
      }
      node.children.sort((a, b) => {
        if (a.highValue !== b.highValue) return a.highValue ? -1 : 1
        const ac = (a.confidence ?? 0)
        const bc = (b.confidence ?? 0)
        if (ac !== bc) return bc - ac
        return a.label.localeCompare(b.label)
      })
    } else {
      node.children = undefined
    }
    node.highValue = anyHV
    return anyHV
  }
  finalize(root)

  return root.children ?? []
}

function matchesEntry(node: PathNode, filter: PathFilter, search: string): boolean {
  if (!node.isLeaf) return false
  if (search && !node.fullPath.toLowerCase().includes(search.toLowerCase())) {
    return false
  }
  switch (filter) {
    case 'all':
      return true
    case 'high':
      return node.selfHighValue
    case 's200':
      return node.status === 200
    case 's403':
      return node.status === 403
  }
}

function filterTree(
  nodes: PathNode[],
  filter: PathFilter,
  search: string,
): PathNode[] {
  const out: PathNode[] = []
  for (const node of nodes) {
    const children = node.children
      ? filterTree(node.children, filter, search)
      : []
    const selfHit = matchesEntry(node, filter, search)
    if (selfHit || children.length) {
      out.push({
        ...node,
        children: children.length ? children : undefined,
      })
    }
  }
  return out
}

function collectHighValueKeys(nodes: PathNode[], depth: number, maxDepth: number, acc: string[]): void {
  for (const node of nodes) {
    if (node.highValue) {
      acc.push(node.key)
      if (depth < maxDepth && node.children) {
        collectHighValueKeys(node.children, depth + 1, maxDepth, acc)
      }
    }
  }
}

export function usePathTree(
  entries: MaybeRefOrGetter<PathEntry[]>,
  filter: MaybeRefOrGetter<PathFilter> = () => 'all',
  search: MaybeRefOrGetter<string> = () => '',
) {
  const fullTree = computed(() => buildTree(toValue(entries) ?? []))

  const tree = computed(() => {
    const f = toValue(filter)
    const s = (toValue(search) ?? '').trim()
    if (f === 'all' && !s) return fullTree.value
    return filterTree(fullTree.value, f, s)
  })

  const leafCount = computed(() => {
    let n = 0
    const walk = (nodes: PathNode[]) => {
      for (const node of nodes) {
        if (node.isLeaf) n++
        if (node.children) walk(node.children)
      }
    }
    walk(tree.value)
    return n
  })

  const highValueExpandKeys = computed(() => {
    const acc: string[] = []
    collectHighValueKeys(fullTree.value, 0, 2, acc)
    return acc
  })

  const allKeys = computed(() => {
    const acc: string[] = []
    const walk = (nodes: PathNode[]) => {
      for (const node of nodes) {
        acc.push(node.key)
        if (node.children) walk(node.children)
      }
    }
    walk(fullTree.value)
    return acc
  })

  return {
    fullTree,
    tree,
    leafCount,
    highValueExpandKeys,
    allKeys,
  }
}
