import React, { useState, useEffect, useCallback, useRef } from 'react'
import { searchApi } from '../services/api'
import { useNavigate, useSearchParams } from 'react-router-dom'

interface SearchHit {
    entity: string
    id: number
    email_id?: number
    title: string
    subtitle: string
    meta: string
    matched_fields: string[]
    severity: string | null
    url: string
}

interface SearchResult {
    query: string
    total: number
    results: SearchHit[]
}

const ENTITY_LABELS: Record<string, string> = {
    email: 'Email',
    threat: 'Threat',
    alert: 'Alert',
    case: 'Case',
}

const ENTITY_ICONS: Record<string, string> = {
    email: '📧',
    threat: '⚠️',
    alert: '🔔',
    case: '📁',
}

const SEVERITY_COLORS: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-300 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    safe: 'bg-green-500/20 text-green-300 border-green-500/30',
}

function SeverityBadge({ severity }: { severity: string | null }) {
    if (!severity || severity === 'safe') return null
    const cls = SEVERITY_COLORS[severity] ?? 'bg-slate-500/20 text-slate-300 border-slate-500/30'
    return (
        <span className={`inline-block text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border ${cls}`}>
            {severity}
        </span>
    )
}

const ENTITY_FILTERS = ['all', 'emails', 'threats', 'alerts', 'cases']

export default function SearchPage() {
    const [searchParams, setSearchParams] = useSearchParams()
    const navigate = useNavigate()

    const initialQ = searchParams.get('q') ?? ''
    const initialEntity = searchParams.get('entity') ?? 'all'

    const [query, setQuery] = useState(initialQ)
    const [activeEntity, setActiveEntity] = useState(initialEntity)
    const [result, setResult] = useState<SearchResult | null>(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)

    const inputRef = useRef<HTMLInputElement>(null)

    const doSearch = useCallback(async (q: string, entity: string) => {
        if (q.trim().length < 2) {
            setResult(null)
            return
        }
        setLoading(true)
        setError(null)
        try {
            const params: any = { q: q.trim(), per_page: 50 }
            if (entity !== 'all') params.entity = entity
            const res = await searchApi.search(params)
            setResult(res.data)
        } catch (e: any) {
            setError(e.response?.data?.detail ?? 'Search failed')
        }
        setLoading(false)
    }, [])

    // Debounce search as user types
    useEffect(() => {
        const timer = setTimeout(() => {
            if (query.trim().length >= 2) {
                setSearchParams({ q: query.trim(), entity: activeEntity }, { replace: true })
                doSearch(query, activeEntity)
            } else {
                setResult(null)
            }
        }, 350)
        return () => clearTimeout(timer)
    }, [query, activeEntity]) // eslint-disable-line react-hooks/exhaustive-deps

    // Focus input on mount
    useEffect(() => {
        inputRef.current?.focus()
    }, [])

    // Group results by entity type
    const grouped: Record<string, SearchHit[]> = {}
    for (const hit of result?.results ?? []) {
        if (!grouped[hit.entity]) grouped[hit.entity] = []
        grouped[hit.entity].push(hit)
    }

    return (
        <div className="max-w-3xl mx-auto px-4 py-6">
            {/* Search input */}
            <div className="mb-6">
                <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">🔍</span>
                    <input
                        ref={inputRef}
                        type="text"
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                        placeholder="Search emails, threats, alerts, cases…"
                        className="w-full bg-slate-800 border border-slate-600 rounded-xl pl-10 pr-4 py-3 text-slate-100
                       placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                       text-sm transition"
                    />
                    {loading && (
                        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 text-xs animate-pulse">
                            searching…
                        </span>
                    )}
                </div>
            </div>

            {/* Entity filter tabs */}
            <div className="flex gap-2 mb-5 flex-wrap">
                {ENTITY_FILTERS.map(e => (
                    <button
                        key={e}
                        onClick={() => setActiveEntity(e)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition capitalize
              ${activeEntity === e
                                ? 'bg-blue-600 text-white'
                                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
                    >
                        {e}
                    </button>
                ))}
            </div>

            {/* Error */}
            {error && (
                <div className="bg-red-900/30 border border-red-500/30 rounded-lg p-3 text-red-300 text-sm mb-4">
                    {error}
                </div>
            )}

            {/* Empty state */}
            {!loading && !error && query.trim().length >= 2 && result && result.total === 0 && (
                <div className="text-center py-16 text-slate-400">
                    <p className="text-4xl mb-3">🔍</p>
                    <p className="font-medium">No results for <span className="text-slate-200">"{result.query}"</span></p>
                    <p className="text-sm mt-1">Try a different search term or broaden the entity filter.</p>
                </div>
            )}

            {/* Too-short hint */}
            {query.trim().length > 0 && query.trim().length < 2 && (
                <p className="text-slate-500 text-sm text-center py-8">Type at least 2 characters to search.</p>
            )}

            {/* Results */}
            {result && result.total > 0 && (
                <div className="space-y-6">
                    <p className="text-slate-400 text-xs">
                        {result.total} result{result.total !== 1 ? 's' : ''} for{' '}
                        <span className="text-slate-200 font-medium">"{result.query}"</span>
                    </p>

                    {Object.entries(grouped).map(([entityType, hits]) => (
                        <div key={entityType}>
                            <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-2">
                                {ENTITY_ICONS[entityType]} {ENTITY_LABELS[entityType] ?? entityType}s ({hits.length})
                            </h2>
                            <div className="space-y-2">
                                {hits.map(hit => (
                                    <button
                                        key={`${hit.entity}-${hit.id}`}
                                        onClick={() => navigate(hit.url)}
                                        className="w-full text-left bg-slate-800 hover:bg-slate-750 border border-slate-700
                               hover:border-slate-500 rounded-xl px-4 py-3 transition group"
                                    >
                                        <div className="flex items-start justify-between gap-2">
                                            <div className="min-w-0">
                                                <p className="text-slate-100 text-sm font-medium truncate group-hover:text-white">
                                                    {hit.title}
                                                </p>
                                                {hit.subtitle && (
                                                    <p className="text-slate-400 text-xs truncate mt-0.5">{hit.subtitle}</p>
                                                )}
                                                <p className="text-slate-500 text-xs mt-1">{hit.meta}</p>
                                            </div>
                                            <div className="flex-shrink-0 flex flex-col items-end gap-1">
                                                <SeverityBadge severity={hit.severity} />
                                                {hit.matched_fields.length > 0 && (
                                                    <span className="text-[10px] text-slate-600">
                                                        matched: {hit.matched_fields.join(', ')}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </button>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}