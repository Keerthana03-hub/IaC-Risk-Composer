/**
 * Deterministic layered layout for the infrastructure map. The backend gives
 * nodes and edges but no coordinates. An edge source → target means "source
 * references target", so referenced resources sit on the row below.
 * Only real nodes/edges are used; nothing is invented.
 */
export const NODE_W = 230
export const NODE_H = 92
const GAP_X = 50
const GAP_Y = 90
const MAX_PER_ROW = 4

export function layoutNodes(nodes = [], edges = []) {
  const ids = new Set(nodes.map(n => n.id))
  const valid = edges.filter(e => ids.has(e.source) && ids.has(e.target) && e.source !== e.target)

  const connected = new Set()
  valid.forEach(e => { connected.add(e.source); connected.add(e.target) })

  // Longest-path layering (bounded so cycles cannot loop forever)
  const level = Object.fromEntries(nodes.map(n => [n.id, 0]))
  for (let i = 0; i < nodes.length; i++) {
    let changed = false
    for (const e of valid) {
      if (level[e.target] < level[e.source] + 1 && level[e.source] + 1 < nodes.length) {
        level[e.target] = level[e.source] + 1
        changed = true
      }
    }
    if (!changed) break
  }

  const rows = []
  const byLevel = new Map()
  nodes.filter(n => connected.has(n.id)).forEach(n => {
    if (!byLevel.has(level[n.id])) byLevel.set(level[n.id], [])
    byLevel.get(level[n.id]).push(n)
  })
  ;[...byLevel.keys()].sort((a, b) => a - b).forEach(l => chunk(byLevel.get(l)).forEach(r => rows.push(r)))
  chunk(nodes.filter(n => !connected.has(n.id))).forEach(r => rows.push(r)) // isolated resources last

  const positions = {}
  rows.forEach((row, r) => {
    row.forEach((n, i) => {
      positions[n.id] = { x: (i - (row.length - 1) / 2) * (NODE_W + GAP_X), y: r * (NODE_H + GAP_Y) }
    })
  })
  return { positions, validEdges: valid }
}

function chunk(list) {
  const out = []
  for (let i = 0; i < list.length; i += MAX_PER_ROW) out.push(list.slice(i, i + MAX_PER_ROW))
  return out
}
