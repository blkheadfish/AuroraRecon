import { describe, it, expect } from 'vitest'
import { ref } from 'vue'
import {
  usePathTree,
  type PathEntry,
  type PathNode,
  type PathFilter,
} from '../usePathTree'

function makeEntry(
  path: string,
  overrides: Partial<PathEntry> = {},
): PathEntry {
  return {
    path,
    status: 200,
    confidence: 0.8,
    highValue: false,
    badge: '',
    hints: [],
    ...overrides,
  }
}

function findNode(nodes: readonly PathNode[], fullPath: string): PathNode | undefined {
  for (const node of nodes) {
    if (node.fullPath === fullPath) return node
    if (node.children) {
      const hit = findNode(node.children, fullPath)
      if (hit) return hit
    }
  }
  return undefined
}

describe('usePathTree', () => {
  describe('buildTree', () => {
    it('nests paths by segments', () => {
      const entries: PathEntry[] = [
        makeEntry('/admin'),
        makeEntry('/admin/users'),
        makeEntry('/api/v1/users'),
      ]
      const { tree } = usePathTree(entries)
      const root = tree.value
      const labels = root.map(n => n.label).sort()
      expect(labels).toEqual(['admin', 'api'])
      expect(findNode(root, '/admin/users')?.isLeaf).toBe(true)
      expect(findNode(root, '/api/v1/users')?.isLeaf).toBe(true)
      const apiV1 = findNode(root, '/api/v1')
      expect(apiV1).toBeDefined()
      expect(apiV1!.isLeaf).toBe(false)
    })

    it('marks a node as both leaf and container when it has children', () => {
      const entries: PathEntry[] = [
        makeEntry('/admin', { status: 200 }),
        makeEntry('/admin/users'),
      ]
      const { tree } = usePathTree(entries)
      const admin = findNode(tree.value, '/admin')!
      expect(admin.isLeaf).toBe(true)
      expect(admin.status).toBe(200)
      expect(admin.children).toBeDefined()
      expect(admin.children!.length).toBe(1)
    })

    it('propagates highValue up to ancestors', () => {
      const entries: PathEntry[] = [
        makeEntry('/api'),
        makeEntry('/api/admin/panel', { highValue: true, badge: 'admin' }),
        makeEntry('/api/public'),
      ]
      const { tree } = usePathTree(entries)
      const api = findNode(tree.value, '/api')!
      const apiAdmin = findNode(tree.value, '/api/admin')!
      const apiPublic = findNode(tree.value, '/api/public')!

      expect(api.highValue).toBe(true)
      expect(apiAdmin.highValue).toBe(true)
      expect(apiPublic.highValue).toBe(false)
      expect(apiPublic.selfHighValue).toBe(false)
      expect(apiAdmin.selfHighValue).toBe(false) // hv came from /api/admin/panel
    })

    it('sorts children with highValue first, then by confidence, then label', () => {
      const entries: PathEntry[] = [
        makeEntry('/root/z_low', { confidence: 0.3 }),
        makeEntry('/root/a_mid', { confidence: 0.7 }),
        makeEntry('/root/m_hv', { confidence: 0.4, highValue: true }),
      ]
      const { tree } = usePathTree(entries)
      const root = findNode(tree.value, '/root')!
      const labels = (root.children ?? []).map(n => n.label)
      expect(labels).toEqual(['m_hv', 'a_mid', 'z_low'])
    })
  })

  describe('filtering & search', () => {
    const buildEntries = (): PathEntry[] => [
      makeEntry('/admin', { status: 403, highValue: true, badge: 'admin' }),
      makeEntry('/admin/users', { status: 200, highValue: true, badge: 'admin' }),
      makeEntry('/public', { status: 200 }),
      makeEntry('/public/static', { status: 200 }),
      makeEntry('/forbidden-only', { status: 403 }),
    ]

    it('filter=high keeps only high-value leaves and their ancestors', () => {
      const entries = buildEntries()
      const filter = ref<PathFilter>('high')
      const { tree } = usePathTree(entries, filter)
      const allFullPaths: string[] = []
      const walk = (nodes: readonly PathNode[]) => {
        for (const n of nodes) {
          allFullPaths.push(n.fullPath)
          if (n.children) walk(n.children)
        }
      }
      walk(tree.value)
      expect(allFullPaths).toContain('/admin')
      expect(allFullPaths).toContain('/admin/users')
      expect(allFullPaths).not.toContain('/public')
      expect(allFullPaths).not.toContain('/forbidden-only')
    })

    it('filter=s200 keeps only leaves with status 200', () => {
      const entries = buildEntries()
      const filter = ref<PathFilter>('s200')
      const { tree } = usePathTree(entries, filter)
      const adminRoot = findNode(tree.value, '/admin')
      expect(adminRoot).toBeDefined()       // kept because /admin/users is 200
      expect(adminRoot!.isLeaf).toBe(true)   // but /admin itself is 403
      // the 403-only leaf should be filtered out
      expect(findNode(tree.value, '/forbidden-only')).toBeUndefined()
    })

    it('filter=s403 keeps only leaves with status 403', () => {
      const entries = buildEntries()
      const filter = ref<PathFilter>('s403')
      const { tree } = usePathTree(entries, filter)
      expect(findNode(tree.value, '/admin')).toBeDefined()
      expect(findNode(tree.value, '/admin/users')).toBeUndefined()
      expect(findNode(tree.value, '/forbidden-only')).toBeDefined()
      expect(findNode(tree.value, '/public/static')).toBeUndefined()
    })

    it('search substring is case-insensitive and keeps matching subtrees', () => {
      const entries = buildEntries()
      const search = ref('USER')
      const { tree } = usePathTree(entries, () => 'all' as PathFilter, search)
      expect(findNode(tree.value, '/admin/users')).toBeDefined()
      expect(findNode(tree.value, '/admin')).toBeDefined()
      expect(findNode(tree.value, '/public')).toBeUndefined()
      expect(findNode(tree.value, '/forbidden-only')).toBeUndefined()
    })

    it('leafCount reflects the filtered tree', () => {
      const entries = buildEntries()
      const filter = ref<PathFilter>('all')
      const { leafCount, tree } = usePathTree(entries, filter)
      expect(leafCount.value).toBe(entries.length)
      filter.value = 'high'
      expect(leafCount.value).toBe(2)
      expect(tree.value.length).toBeGreaterThan(0)
    })
  })

  describe('expand keys', () => {
    it('highValueExpandKeys covers hv ancestors up to depth 2', () => {
      const entries: PathEntry[] = [
        makeEntry('/alpha/beta/gamma/leaf', { highValue: true }),
      ]
      const { highValueExpandKeys } = usePathTree(entries)
      // depth 0 -> /alpha, depth 1 -> /alpha/beta, depth 2 -> /alpha/beta/gamma
      expect(highValueExpandKeys.value).toEqual(
        expect.arrayContaining(['/alpha', '/alpha/beta', '/alpha/beta/gamma']),
      )
      // leaf itself (depth 3) should NOT be auto-expanded
      expect(highValueExpandKeys.value).not.toContain('/alpha/beta/gamma/leaf')
    })

    it('allKeys enumerates every node in the full (unfiltered) tree', () => {
      const entries: PathEntry[] = [
        makeEntry('/a/b'),
        makeEntry('/a/c'),
      ]
      const { allKeys } = usePathTree(entries, () => 'high' as PathFilter)
      // Even when filter excludes everything, allKeys is based on fullTree
      expect(allKeys.value.sort()).toEqual(['/a', '/a/b', '/a/c'])
    })
  })
})
