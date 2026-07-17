/**
 * ExportButton — a small dropdown that triggers a CSV download for the
 * given entity. Drop it into any page header.
 *
 * Usage:
 *   <ExportButton entity="emails" />
 *   <ExportButton entity="threats" params={{ severity: 'high' }} />
 *   <ExportButton entity="alerts" params={{ acknowledged: false }} />
 */
import React, { useRef, useState } from 'react'
import { exportApi, downloadBlob } from '../services/api'

type ExportEntity = 'emails' | 'threats' | 'alerts'

interface ExportButtonProps {
    entity: ExportEntity
    params?: Record<string, string | boolean | undefined>
    className?: string
}

export function ExportButton({ entity, params, className = '' }: ExportButtonProps) {
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)

    async function handleExport() {
        setLoading(true)
        setError(null)
        try {
            let res: any
            if (entity === 'emails') res = await exportApi.emailsCsv(params as any)
            else if (entity === 'threats') res = await exportApi.threatsCsv(params as any)
            else res = await exportApi.alertsCsv(params as any)

            const now = new Date().toISOString().slice(0, 16).replace('T', '_').replace(':', '')
            downloadBlob(res.data, `threatshield_${entity}_${now}.csv`)
        } catch (e: any) {
            setError('Export failed')
            setTimeout(() => setError(null), 3000)
        }
        setLoading(false)
    }

    return (
        <button
            onClick={handleExport}
            disabled={loading}
            title={`Export ${entity} to CSV`}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
        bg-slate-700 hover:bg-slate-600 text-slate-200 hover:text-white border border-slate-600
        disabled:opacity-50 disabled:cursor-not-allowed transition ${className}`}
        >
            {loading ? (
                <>
                    <span className="animate-spin">⏳</span> Exporting…
                </>
            ) : error ? (
                <span className="text-red-400">{error}</span>
            ) : (
                <>
                    <span>⬇</span> Export CSV
                </>
            )}
        </button>
    )
}