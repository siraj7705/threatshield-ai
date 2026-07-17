// LOCATION: threatshield-ai/frontend/src/pages/GraphPage.tsx
import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react'
import { graphApi } from '../services/api'
import { Card, Spinner, EmptyState } from '../components/common'

// ── Types ─────────────────────────────────────────────────────────────────────
interface GraphNode {
    id: string
    node_type: 'email' | 'sender' | 'domain' | 'ip' | 'url' | 'case'
    label: string
    threat_score?: number
    threat_type?: string
    severity?: string
    country?: string
    is_vpn?: boolean
    is_tor?: boolean
    domain?: string
    email?: string
    ip?: string
}

interface GraphEdge {
    source: string
    target: string
    edge_type: string
}

interface GraphSummary {
    nodes: number
    edges: number
    clusters: number
    largest_cluster_size: number
    node_types: Record<string, number>
    density: number
}

interface CentralNode {
    id: string
    node_type: string
    label: string
    centrality_score: number
    degree: number
}

interface Cluster {
    cluster_id: number
    size: number
    nodes: string[]
    node_types: Record<string, number>
    dominant_severity: string
    email_count: number
    domain_count: number
    ip_count: number
}

// ── Colour & style config ─────────────────────────────────────────────────────
const NODE_STYLE: Record<string, { color: string; bg: string; icon: string; label: string }> = {
    email:  { color: '#60a5fa', bg: '#1e3a5f', icon: '📧', label: 'Email' },
    sender: { color: '#a78bfa', bg: '#2e1f5e', icon: '👤', label: 'Sender' },
    domain: { color: '#22d3ee', bg: '#0e3d4a', icon: '🌐', label: 'Domain' },
    ip:     { color: '#fb923c', bg: '#4a2810', icon: '🖥️', label: 'IP' },
    url:    { color: '#facc15', bg: '#3d3510', icon: '🔗', label: 'URL' },
    case:   { color: '#4ade80', bg: '#103d1f', icon: '📁', label: 'Case' },
}

const EDGE_STYLE: Record<string, { color: string; label: string }> = {
    SENT_BY:         { color: '#a78bfa', label: 'Sent By' },
    BELONGS_TO:      { color: '#22d3ee', label: 'Belongs To' },
    ORIGINATED_FROM: { color: '#fb923c', label: 'Origin IP' },
    CONTAINS_URL:    { color: '#facc15', label: 'Contains URL' },
    LINKED_TO:       { color: '#4ade80', label: 'Linked To' },
}

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#ef4444',
    high_risk: '#f97316',
    high: '#f97316',
    warning: '#eab308',
    safe: '#22c55e',
}

function nodeColor(node: GraphNode): string {
    if (node.node_type === 'email' && node.severity) {
        return SEVERITY_COLORS[node.severity] || NODE_STYLE.email.color
    }
    return NODE_STYLE[node.node_type]?.color || '#94a3b8'
}

// ── Grouped layout algorithm ──────────────────────────────────────────────────
// Instead of force-directed chaos, arrange nodes by type in clear zones.
interface LayoutPos { x: number; y: number }

function computeGroupedLayout(
    nodes: GraphNode[],
    edges: GraphEdge[],
    width: number,
    height: number,
): Map<string, LayoutPos> {
    const positions = new Map<string, LayoutPos>()
    const cx = width / 2
    const cy = height / 2

    // Group nodes by type
    const groups: Record<string, GraphNode[]> = {}
    nodes.forEach(n => {
        if (!groups[n.node_type]) groups[n.node_type] = []
        groups[n.node_type].push(n)
    })

    // Zone assignments – each type gets a sector of the canvas
    // Emails in the center, related types around them
    const zoneConfig: Record<string, { angle: number; radiusFactor: number }> = {
        email:  { angle: 0,               radiusFactor: 0 },     // Center
        sender: { angle: -Math.PI / 2,    radiusFactor: 0.35 },  // Top
        domain: { angle: Math.PI / 4,     radiusFactor: 0.4 },   // Top-right
        ip:     { angle: -Math.PI * 3/4,  radiusFactor: 0.4 },   // Top-left
        url:    { angle: Math.PI / 2,     radiusFactor: 0.42 },   // Bottom
        case:   { angle: Math.PI * 3/4,   radiusFactor: 0.38 },  // Bottom-right
    }

    Object.entries(groups).forEach(([type, typeNodes]) => {
        const config = zoneConfig[type] || { angle: 0, radiusFactor: 0.3 }
        const zoneRadius = Math.min(width, height) * config.radiusFactor
        const zoneCx = cx + Math.cos(config.angle) * zoneRadius
        const zoneCy = cy + Math.sin(config.angle) * zoneRadius

        if (typeNodes.length === 1) {
            positions.set(typeNodes[0].id, { x: zoneCx, y: zoneCy })
        } else {
            // Arrange nodes in a mini-circle or arc within their zone
            const count = typeNodes.length
            const spacing = Math.min(55, 200 / Math.max(count, 1))
            const groupRadius = Math.max(spacing, count * spacing / (2 * Math.PI))
            const capped = Math.min(groupRadius, Math.min(width, height) * 0.15)

            typeNodes.forEach((n, i) => {
                const angle = (2 * Math.PI * i) / count - Math.PI / 2
                positions.set(n.id, {
                    x: zoneCx + capped * Math.cos(angle),
                    y: zoneCy + capped * Math.sin(angle),
                })
            })
        }
    })

    return positions
}

// ── Curved edge path ──────────────────────────────────────────────────────────
function curvedEdgePath(
    x1: number, y1: number,
    x2: number, y2: number,
    edgeIndex: number,
    totalParallel: number,
): string {
    const dx = x2 - x1
    const dy = y2 - y1
    const dist = Math.sqrt(dx * dx + dy * dy)

    // Offset for parallel edges between the same pair
    const offset = totalParallel > 1 ? (edgeIndex - (totalParallel - 1) / 2) * 20 : 0

    // Perpendicular offset direction
    const nx = -dy / (dist || 1)
    const ny = dx / (dist || 1)

    // Control point at midpoint + perpendicular offset + slight curve
    const curvature = Math.min(dist * 0.15, 40) + Math.abs(offset)
    const cpx = (x1 + x2) / 2 + nx * curvature * Math.sign(offset || 1)
    const cpy = (y1 + y2) / 2 + ny * curvature * Math.sign(offset || 1)

    return `M ${x1} ${y1} Q ${cpx} ${cpy} ${x2} ${y2}`
}

// ── SVG Graph component ───────────────────────────────────────────────────────
function GraphSVG({
    nodes, edges, onNodeClick, selectedId,
}: {
    nodes: GraphNode[]
    edges: GraphEdge[]
    onNodeClick: (n: GraphNode) => void
    selectedId: string | null
}) {
    const containerRef = useRef<HTMLDivElement>(null)
    const [dimensions, setDimensions] = useState({ w: 900, h: 560 })
    const [hoveredId, setHoveredId] = useState<string | null>(null)
    const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 })
    const dragRef = useRef<{ dragging: boolean; lastX: number; lastY: number }>({
        dragging: false, lastX: 0, lastY: 0,
    })

    const W = dimensions.w
    const H = dimensions.h

    // Responsive sizing
    useEffect(() => {
        const container = containerRef.current
        if (!container) return
        const ro = new ResizeObserver(entries => {
            const entry = entries[0]
            if (entry) {
                const w = Math.max(600, entry.contentRect.width)
                setDimensions({ w, h: Math.max(480, Math.min(640, w * 0.6)) })
            }
        })
        ro.observe(container)
        return () => ro.disconnect()
    }, [])

    // Compute positions
    const positions = useMemo(() => computeGroupedLayout(nodes, edges, W, H), [nodes, edges, W, H])

    // Build adjacency for highlighting
    const connectedSet = useMemo(() => {
        const activeId = hoveredId || selectedId
        if (!activeId) return null
        const set = new Set<string>()
        set.add(activeId)
        edges.forEach(e => {
            if (e.source === activeId) set.add(e.target)
            if (e.target === activeId) set.add(e.source)
        })
        return set
    }, [hoveredId, selectedId, edges])

    // Build edge index map for parallel edges
    const edgeParallelInfo = useMemo(() => {
        const pairCount = new Map<string, number>()
        const pairIndex = new Map<string, number>()
        edges.forEach(e => {
            const key = [e.source, e.target].sort().join('|')
            pairCount.set(key, (pairCount.get(key) || 0) + 1)
        })
        const pairCurrent = new Map<string, number>()
        return edges.map(e => {
            const key = [e.source, e.target].sort().join('|')
            const idx = pairCurrent.get(key) || 0
            pairCurrent.set(key, idx + 1)
            return { index: idx, total: pairCount.get(key) || 1 }
        })
    }, [edges])

    // Zoom/pan handlers
    const handleWheel = useCallback((e: React.WheelEvent) => {
        e.preventDefault()
        const delta = e.deltaY > 0 ? 0.92 : 1.08
        setTransform(t => {
            const newScale = Math.max(0.3, Math.min(3, t.scale * delta))
            const rect = containerRef.current!.getBoundingClientRect()
            const mx = e.clientX - rect.left
            const my = e.clientY - rect.top
            return {
                scale: newScale,
                x: mx - (mx - t.x) * (newScale / t.scale),
                y: my - (my - t.y) * (newScale / t.scale),
            }
        })
    }, [])

    const handleMouseDown = useCallback((e: React.MouseEvent) => {
        if ((e.target as HTMLElement).closest('.graph-node')) return
        dragRef.current = { dragging: true, lastX: e.clientX, lastY: e.clientY }
    }, [])

    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        if (!dragRef.current.dragging) return
        const dx = e.clientX - dragRef.current.lastX
        const dy = e.clientY - dragRef.current.lastY
        dragRef.current.lastX = e.clientX
        dragRef.current.lastY = e.clientY
        setTransform(t => ({ ...t, x: t.x + dx, y: t.y + dy }))
    }, [])

    const handleMouseUp = useCallback(() => {
        dragRef.current.dragging = false
    }, [])

    const resetView = useCallback(() => setTransform({ x: 0, y: 0, scale: 1 }), [])

    // Node radius based on type
    const nodeR = (type: string) => {
        if (type === 'email') return 22
        if (type === 'domain' || type === 'ip') return 18
        return 16
    }

    return (
        <div ref={containerRef} className="relative w-full" style={{ minHeight: 480 }}>
            <svg
                width={W} height={H}
                viewBox={`0 0 ${W} ${H}`}
                style={{ width: '100%', height: H, display: 'block', background: '#0b1120', borderRadius: 12, cursor: dragRef.current.dragging ? 'grabbing' : 'grab' }}
                onWheel={handleWheel}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={() => { handleMouseUp(); setHoveredId(null) }}
            >
                {/* Definitions */}
                <defs>
                    {/* Radial background gradient */}
                    <radialGradient id="bgGrad" cx="50%" cy="50%" r="70%">
                        <stop offset="0%" stopColor="#131c2e" />
                        <stop offset="100%" stopColor="#0b1120" />
                    </radialGradient>
                    {/* Glow filters per node type */}
                    {Object.entries(NODE_STYLE).map(([type, style]) => (
                        <filter key={type} id={`glow-${type}`} x="-50%" y="-50%" width="200%" height="200%">
                            <feGaussianBlur stdDeviation="6" result="blur" />
                            <feFlood floodColor={style.color} floodOpacity="0.4" result="color" />
                            <feComposite in="color" in2="blur" operator="in" result="glow" />
                            <feMerge>
                                <feMergeNode in="glow" />
                                <feMergeNode in="SourceGraphic" />
                            </feMerge>
                        </filter>
                    ))}
                    {/* Arrow markers for edges */}
                    {Object.entries(EDGE_STYLE).map(([type, style]) => (
                        <marker key={type} id={`arrow-${type}`} viewBox="0 0 10 7" refX="10" refY="3.5"
                            markerWidth="8" markerHeight="6" orient="auto-start-reverse" fill={style.color}>
                            <polygon points="0 0, 10 3.5, 0 7" opacity="0.7" />
                        </marker>
                    ))}
                </defs>

                {/* Background */}
                <rect width={W} height={H} fill="url(#bgGrad)" rx="12" />

                {/* Subtle grid dots */}
                <g opacity="0.08">
                    {Array.from({ length: Math.floor(W / 40) }).map((_, xi) =>
                        Array.from({ length: Math.floor(H / 40) }).map((_, yi) => (
                            <circle key={`${xi}-${yi}`} cx={xi * 40 + 20} cy={yi * 40 + 20} r="1" fill="#94a3b8" />
                        ))
                    )}
                </g>

                {/* Zone labels - faint type indicators */}
                <g opacity="0.06" fontFamily="Inter, system-ui, sans-serif" fontSize="48" fontWeight="700" textAnchor="middle" dominantBaseline="central" fill="#94a3b8">
                    <text x={W / 2} y={H * 0.12}>SENDERS</text>
                    <text x={W * 0.18} y={H * 0.32}>IPs</text>
                    <text x={W * 0.82} y={H * 0.32}>DOMAINS</text>
                    <text x={W / 2} y={H / 2}>EMAILS</text>
                    <text x={W / 2} y={H * 0.85}>URLs</text>
                </g>

                {/* Transform group for zoom/pan */}
                <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`}>
                    {/* ── Edges ── */}
                    {edges.map((edge, idx) => {
                        const ps = positions.get(edge.source)
                        const pt = positions.get(edge.target)
                        if (!ps || !pt) return null

                        const style = EDGE_STYLE[edge.edge_type] || { color: '#475569', label: edge.edge_type }
                        const parallel = edgeParallelInfo[idx]
                        const path = curvedEdgePath(ps.x, ps.y, pt.x, pt.y, parallel.index, parallel.total)

                        const isHighlighted = connectedSet && connectedSet.has(edge.source) && connectedSet.has(edge.target)
                        const isDimmed = connectedSet && !isHighlighted

                        return (
                            <g key={`${edge.source}-${edge.target}-${idx}`}>
                                <path
                                    d={path}
                                    fill="none"
                                    stroke={isDimmed ? '#1e293b' : style.color}
                                    strokeWidth={isHighlighted ? 2.5 : 1.5}
                                    strokeOpacity={isDimmed ? 0.15 : isHighlighted ? 0.85 : 0.35}
                                    markerEnd={isDimmed ? undefined : `url(#arrow-${edge.edge_type})`}
                                    style={{ transition: 'all 0.3s ease' }}
                                />
                                {/* Edge label on hover – show near midpoint */}
                                {isHighlighted && (
                                    <text
                                        x={(ps.x + pt.x) / 2}
                                        y={(ps.y + pt.y) / 2 - 8}
                                        textAnchor="middle"
                                        fill={style.color}
                                        fontSize="9"
                                        fontFamily="Inter, system-ui, sans-serif"
                                        fontWeight="600"
                                        opacity="0.9"
                                    >
                                        {style.label}
                                    </text>
                                )}
                            </g>
                        )
                    })}

                    {/* ── Nodes ── */}
                    {nodes.map(node => {
                        const p = positions.get(node.id)
                        if (!p) return null

                        const color = nodeColor(node)
                        const style = NODE_STYLE[node.node_type] || NODE_STYLE.email
                        const R = nodeR(node.node_type)
                        const isSelected = node.id === selectedId
                        const isHovered = node.id === hoveredId
                        const isDimmed = connectedSet && !connectedSet.has(node.id)
                        const isActive = isSelected || isHovered
                        const label = node.label.length > 18 ? node.label.slice(0, 16) + '…' : node.label

                        return (
                            <g
                                key={node.id}
                                className="graph-node"
                                style={{
                                    cursor: 'pointer',
                                    transition: 'opacity 0.3s ease, transform 0.2s ease',
                                    opacity: isDimmed ? 0.15 : 1,
                                }}
                                onClick={() => onNodeClick(node)}
                                onMouseEnter={() => setHoveredId(node.id)}
                                onMouseLeave={() => setHoveredId(null)}
                            >
                                {/* Outer glow ring on active */}
                                {isActive && (
                                    <circle cx={p.x} cy={p.y} r={R + 10}
                                        fill="none" stroke={color} strokeWidth="1.5"
                                        strokeDasharray="4 3" opacity="0.5">
                                        <animateTransform attributeName="transform" type="rotate"
                                            from={`0 ${p.x} ${p.y}`} to={`360 ${p.x} ${p.y}`}
                                            dur="8s" repeatCount="indefinite" />
                                    </circle>
                                )}

                                {/* Selection ring */}
                                {isSelected && (
                                    <circle cx={p.x} cy={p.y} r={R + 5}
                                        fill="none" stroke="#ffffff" strokeWidth="2" opacity="0.4" />
                                )}

                                {/* Main circle */}
                                <circle
                                    cx={p.x} cy={p.y} r={R}
                                    fill={style.bg}
                                    stroke={color}
                                    strokeWidth={isActive ? 2.5 : 1.5}
                                    filter={isActive ? `url(#glow-${node.node_type})` : undefined}
                                />

                                {/* Inner icon */}
                                <text x={p.x} y={p.y + 1} textAnchor="middle" dominantBaseline="central"
                                    fontSize={R * 0.75} style={{ pointerEvents: 'none' }}>
                                    {style.icon}
                                </text>

                                {/* Label pill below node */}
                                <g style={{ pointerEvents: 'none' }}>
                                    <rect
                                        x={p.x - 50} y={p.y + R + 6}
                                        width={100} height={20}
                                        rx={6} fill="#0f172a" fillOpacity="0.85"
                                        stroke="#1e293b" strokeWidth="0.5"
                                    />
                                    <text
                                        x={p.x} y={p.y + R + 16}
                                        textAnchor="middle" dominantBaseline="central"
                                        fill="#e2e8f0"
                                        fontSize="11"
                                        fontFamily="'JetBrains Mono', 'Fira Code', monospace"
                                        fontWeight="500"
                                    >
                                        {label}
                                    </text>
                                </g>

                                {/* Severity indicator dot for emails */}
                                {node.node_type === 'email' && node.severity && (
                                    <circle
                                        cx={p.x + R - 2} cy={p.y - R + 2} r={5}
                                        fill={SEVERITY_COLORS[node.severity] || '#64748b'}
                                        stroke="#0f172a" strokeWidth="1.5"
                                    />
                                )}

                                {/* Threat score badge on hover */}
                                {isActive && node.threat_score !== undefined && (
                                    <g>
                                        <rect x={p.x - 20} y={p.y - R - 22} width={40} height={16} rx={8}
                                            fill={node.threat_score >= 80 ? '#ef444422' : node.threat_score >= 60 ? '#f9731622' : '#22c55e22'}
                                            stroke={node.threat_score >= 80 ? '#ef4444' : node.threat_score >= 60 ? '#f97316' : '#22c55e'}
                                            strokeWidth="1"
                                        />
                                        <text x={p.x} y={p.y - R - 14} textAnchor="middle" dominantBaseline="central"
                                            fontSize="9" fontWeight="700" fontFamily="Inter, system-ui, sans-serif"
                                            fill={node.threat_score >= 80 ? '#ef4444' : node.threat_score >= 60 ? '#f97316' : '#22c55e'}>
                                            {node.threat_score}/100
                                        </text>
                                    </g>
                                )}
                            </g>
                        )
                    })}
                </g>
            </svg>

            {/* Zoom controls overlay */}
            <div className="absolute bottom-3 right-3 flex gap-1.5">
                <button onClick={() => setTransform(t => ({ ...t, scale: Math.min(3, t.scale * 1.25) }))}
                    className="w-8 h-8 rounded-lg bg-slate-800/90 border border-slate-600/50 text-slate-300 hover:bg-slate-700 hover:text-white text-sm font-bold backdrop-blur-sm transition-all"
                    title="Zoom in">+</button>
                <button onClick={() => setTransform(t => ({ ...t, scale: Math.max(0.3, t.scale * 0.8) }))}
                    className="w-8 h-8 rounded-lg bg-slate-800/90 border border-slate-600/50 text-slate-300 hover:bg-slate-700 hover:text-white text-sm font-bold backdrop-blur-sm transition-all"
                    title="Zoom out">−</button>
                <button onClick={resetView}
                    className="h-8 px-3 rounded-lg bg-slate-800/90 border border-slate-600/50 text-slate-300 hover:bg-slate-700 hover:text-white text-xs backdrop-blur-sm transition-all"
                    title="Reset view">⟲ Reset</button>
            </div>

            {/* Zoom indicator */}
            <div className="absolute top-3 right-3 text-[10px] text-slate-500 bg-slate-900/70 px-2 py-1 rounded-md backdrop-blur-sm">
                {Math.round(transform.scale * 100)}%
            </div>
        </div>
    )
}

// ── Node detail panel ─────────────────────────────────────────────────────────
function NodePanel({ node, onClose }: { node: GraphNode; onClose: () => void }) {
    const color = nodeColor(node)
    const style = NODE_STYLE[node.node_type] || NODE_STYLE.email
    return (
        <div className="bg-slate-800/80 backdrop-blur border border-slate-700 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center text-lg"
                        style={{ background: style.bg, border: `1.5px solid ${color}` }}>
                        {style.icon}
                    </div>
                    <div>
                        <span className="text-xs uppercase tracking-wider font-semibold block" style={{ color }}>{node.node_type}</span>
                        <span className="text-[10px] text-slate-500">Node Details</span>
                    </div>
                </div>
                <button onClick={onClose} className="w-7 h-7 rounded-lg bg-slate-700/60 hover:bg-slate-600 text-slate-400 hover:text-white text-sm flex items-center justify-center transition-colors">×</button>
            </div>

            <p className="text-sm font-mono text-slate-200 break-all bg-slate-900/50 px-3 py-2 rounded-lg border border-slate-700/50">{node.label}</p>

            <div className="space-y-2 text-xs text-slate-400">
                {node.threat_score !== undefined && (
                    <div className="space-y-1.5">
                        <div className="flex justify-between">
                            <span>Threat Score</span>
                            <span className={`font-bold ${node.threat_score >= 80 ? 'text-red-400' : node.threat_score >= 60 ? 'text-orange-400' : 'text-green-400'}`}>
                                {node.threat_score}/100
                            </span>
                        </div>
                        <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-500" style={{
                                width: `${node.threat_score}%`,
                                background: `linear-gradient(90deg, ${node.threat_score >= 80 ? '#ef4444' : node.threat_score >= 60 ? '#f97316' : '#22c55e'}, ${node.threat_score >= 80 ? '#dc2626' : node.threat_score >= 60 ? '#ea580c' : '#16a34a'})`
                            }} />
                        </div>
                    </div>
                )}
                {node.threat_type && (
                    <div className="flex justify-between"><span>Type</span><span className="text-slate-300 font-medium">{node.threat_type}</span></div>
                )}
                {node.severity && (
                    <div className="flex justify-between items-center">
                        <span>Severity</span>
                        <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold" style={{
                            background: (SEVERITY_COLORS[node.severity] || '#64748b') + '22',
                            color: SEVERITY_COLORS[node.severity] || '#94a3b8',
                            border: `1px solid ${(SEVERITY_COLORS[node.severity] || '#64748b')}33`,
                        }}>{node.severity}</span>
                    </div>
                )}
                {node.country && <div className="flex justify-between"><span>Country</span><span className="text-slate-300">🏳️ {node.country}</span></div>}
                {node.is_vpn && <div className="flex justify-between"><span>VPN</span><span className="text-orange-400 font-semibold">⚠ Detected</span></div>}
                {node.is_tor && <div className="flex justify-between"><span>Tor Exit Node</span><span className="text-red-400 font-semibold">⚠ Detected</span></div>}
            </div>
        </div>
    )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function GraphPage() {
    const [nodes, setNodes] = useState<GraphNode[]>([])
    const [edges, setEdges] = useState<GraphEdge[]>([])
    const [summary, setSummary] = useState<GraphSummary | null>(null)
    const [central, setCentral] = useState<CentralNode[]>([])
    const [clusters, setClusters] = useState<Cluster[]>([])
    const [loading, setLoading] = useState(true)
    const [days, setDays] = useState(90)
    const [tab, setTab] = useState<'graph' | 'clusters' | 'central'>('graph')
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

    const load = useCallback(async (d: number) => {
        setLoading(true)
        setSelectedNode(null)
        try {
            const [buildRes, clustersRes] = await Promise.all([
                graphApi.build(d),
                graphApi.clusters(d),
            ])
            const data = buildRes.data
            setNodes(data.nodes || [])
            setEdges(data.edges || [])
            setSummary(data.summary || null)
            setCentral(data.central || [])
            setClusters(clustersRes.data || [])
        } catch (err) {
            console.error(err)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { load(days) }, [days])

    const severityBadge = (s: string) => {
        const colors: Record<string, string> = {
            critical: 'bg-red-900/40 text-red-400',
            high: 'bg-orange-900/40 text-orange-400',
            warning: 'bg-yellow-900/40 text-yellow-400',
            safe: 'bg-green-900/40 text-green-400',
        }
        return colors[s] || 'bg-slate-700 text-slate-400'
    }

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-bold text-white">🕸️ Graph Analysis</h1>
                    <p className="text-slate-400 text-sm mt-1">Relationship map of emails, senders, domains, IPs and URLs</p>
                </div>
                <div className="flex gap-2">
                    {[30, 90, 180].map(d => (
                        <button key={d} onClick={() => setDays(d)}
                            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${days === d ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
                                }`}>
                            {d}d
                        </button>
                    ))}
                </div>
            </div>

            {/* Summary cards */}
            {summary && (
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                    {[
                        { label: 'Nodes', value: summary.nodes, color: '#3b82f6' },
                        { label: 'Edges', value: summary.edges, color: '#8b5cf6' },
                        { label: 'Clusters', value: summary.clusters, color: '#06b6d4' },
                        { label: 'Emails', value: summary.node_types?.email || 0, color: '#ef4444' },
                        { label: 'Domains', value: summary.node_types?.domain || 0, color: '#f97316' },
                        { label: 'IPs', value: summary.node_types?.ip || 0, color: '#eab308' },
                    ].map(({ label, value, color }) => (
                        <div key={label} className="bg-slate-800/60 border border-slate-700 rounded-xl p-3 text-center">
                            <p className="text-xl font-bold" style={{ color }}>{value}</p>
                            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
                        </div>
                    ))}
                </div>
            )}

            {/* Legend */}
            <div className="flex flex-wrap gap-4 px-1">
                {Object.entries(NODE_STYLE).map(([type, style]) => (
                    <div key={type} className="flex items-center gap-2 text-xs text-slate-400">
                        <span className="text-sm">{style.icon}</span>
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: style.color, boxShadow: `0 0 6px ${style.color}44` }} />
                        <span className="capitalize font-medium">{style.label}</span>
                    </div>
                ))}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 bg-slate-800/50 p-1 rounded-lg w-fit">
                {(['graph', 'clusters', 'central'] as const).map(t => (
                    <button key={t} onClick={() => setTab(t)}
                        className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors capitalize ${tab === t ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                            }`}>
                        {t === 'graph' ? '🕸️ Graph' : t === 'clusters' ? '🔵 Clusters' : '⭐ Central Nodes'}
                    </button>
                ))}
            </div>

            {loading ? (
                <div className="flex items-center justify-center h-64">
                    <Spinner size="lg" />
                </div>
            ) : nodes.length === 0 ? (
                <Card>
                    <EmptyState icon="🕸️" title="No graph data yet"
                        message="Upload threat emails to build the relationship graph. The graph appears once threats are detected." />
                </Card>
            ) : (
                <>
                    {/* ── Graph tab ── */}
                    {tab === 'graph' && (
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            <div className="lg:col-span-2">
                                <Card className="p-0 overflow-hidden">
                                    <GraphSVG
                                        nodes={nodes}
                                        edges={edges}
                                        onNodeClick={setSelectedNode}
                                        selectedId={selectedNode?.id || null}
                                    />
                                </Card>
                                <div className="flex items-center justify-center gap-2 mt-2">
                                    <span className="inline-flex items-center gap-1 text-[10px] text-slate-600 bg-slate-800/40 px-2 py-1 rounded">🖱️ Scroll to zoom</span>
                                    <span className="inline-flex items-center gap-1 text-[10px] text-slate-600 bg-slate-800/40 px-2 py-1 rounded">✋ Drag to pan</span>
                                    <span className="inline-flex items-center gap-1 text-[10px] text-slate-600 bg-slate-800/40 px-2 py-1 rounded">👆 Click node to inspect</span>
                                </div>
                            </div>
                            <div className="space-y-4">
                                {selectedNode ? (
                                    <NodePanel node={selectedNode} onClose={() => setSelectedNode(null)} />
                                ) : (
                                    <div className="bg-slate-800/40 border border-slate-700/50 rounded-xl p-6 text-center space-y-3">
                                        <p className="text-3xl">👆</p>
                                        <p className="text-sm text-slate-500">Click any node to view details</p>
                                        <p className="text-[10px] text-slate-600">Hover a node to highlight its connections</p>
                                    </div>
                                )}
                                {/* Edge type legend */}
                                <Card>
                                    <p className="text-xs font-semibold text-slate-400 mb-3">Relationship Types</p>
                                    <div className="space-y-2">
                                        {Object.entries(EDGE_STYLE).map(([type, style]) => (
                                            <div key={type} className="flex items-center gap-2.5 text-xs">
                                                <div className="w-6 h-0.5 rounded-full" style={{ background: style.color }} />
                                                <span className="text-slate-400 font-medium">{style.label}</span>
                                                <span className="text-slate-600 text-[10px] ml-auto">{type}</span>
                                            </div>
                                        ))}
                                    </div>
                                </Card>
                            </div>
                        </div>
                    )}

                    {/* ── Clusters tab ── */}
                    {tab === 'clusters' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                            {clusters.length === 0 ? (
                                <div className="col-span-3">
                                    <EmptyState icon="🔵" title="No clusters" message="No connected threat clusters found" />
                                </div>
                            ) : clusters.map(c => (
                                <div key={c.cluster_id}
                                    className="bg-slate-800/60 border border-slate-700 rounded-xl p-4 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-semibold text-slate-200">Cluster #{c.cluster_id}</span>
                                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${severityBadge(c.dominant_severity)}`}>
                                            {c.dominant_severity}
                                        </span>
                                    </div>
                                    <div className="grid grid-cols-3 gap-2 text-center">
                                        <div className="bg-slate-900/60 rounded-lg p-2">
                                            <p className="text-lg font-bold text-blue-400">{c.email_count}</p>
                                            <p className="text-xs text-slate-500">emails</p>
                                        </div>
                                        <div className="bg-slate-900/60 rounded-lg p-2">
                                            <p className="text-lg font-bold text-cyan-400">{c.domain_count}</p>
                                            <p className="text-xs text-slate-500">domains</p>
                                        </div>
                                        <div className="bg-slate-900/60 rounded-lg p-2">
                                            <p className="text-lg font-bold text-orange-400">{c.ip_count}</p>
                                            <p className="text-xs text-slate-500">IPs</p>
                                        </div>
                                    </div>
                                    <p className="text-xs text-slate-500">{c.size} total nodes</p>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* ── Central Nodes tab ── */}
                    {tab === 'central' && (
                        <Card>
                            <p className="text-xs text-slate-500 mb-4">
                                Most connected nodes — high centrality means this node links many threats together (shared sender, IP, or domain).
                            </p>
                            <div className="space-y-2">
                                {central.map((n, i) => (
                                    <div key={n.id}
                                        className="flex items-center gap-3 py-2.5 border-b border-slate-700/30 last:border-0">
                                        <span className="text-slate-600 text-xs w-5 flex-shrink-0">{i + 1}</span>
                                        <span className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                                            style={{ background: NODE_STYLE[n.node_type]?.color || '#94a3b8' }} />
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm text-slate-200 font-mono truncate">{n.label}</p>
                                            <p className="text-xs text-slate-500">{n.node_type} · {n.degree} connections</p>
                                        </div>
                                        <div className="text-right flex-shrink-0">
                                            <p className="text-sm font-semibold text-blue-400">{(n.centrality_score * 100).toFixed(1)}%</p>
                                            <p className="text-xs text-slate-600">centrality</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    )}
                </>
            )}
        </div>
    )
}