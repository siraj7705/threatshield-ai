import React, { useEffect, useState } from 'react'
import { feedbackApi } from '../services/api'
import { Card, Button } from '../components/common'
import { authStore } from '../store/auth'

interface RetrainStatus {
    pending_feedback_samples: number
    total_feedback_in_db: number
    total_false_positives: number
    ready_to_retrain: boolean
    min_samples_required: number
    retrain_status: {
        is_running: boolean
        last_run: string | null
        last_result: any
    }
}

export function RetrainPanel() {
    const [status, setStatus] = useState<RetrainStatus | null>(null)
    const [loading, setLoading] = useState(true)
    const [retraining, setRetraining] = useState(false)
    const [result, setResult] = useState<any>(null)
    const user = authStore.getUser()

    const fetchStatus = async () => {
        try {
            const res = await feedbackApi.status()
            setStatus(res.data)
        } catch (e) {
            console.error('Failed to fetch feedback status', e)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchStatus()
        const interval = setInterval(fetchStatus, 10000)
        return () => clearInterval(interval)
    }, [])

    const handleRetrain = async () => {
        setRetraining(true)
        setResult(null)
        try {
            const res = await feedbackApi.retrain(5)
            setResult(res.data)
            await fetchStatus()
        } catch (e: any) {
            setResult({ success: false, message: e.response?.data?.detail || 'Retrain failed' })
        } finally {
            setRetraining(false)
        }
    }

    if (loading) return null
    if (!status) return null

    const isAdmin = user?.role === 'admin'

    return (
        <Card className="mt-6">
            <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                🧠 Continuous Learning
            </h3>

            <div className="grid grid-cols-3 gap-4 mb-5">
                <div className="bg-slate-800 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-blue-400">{status.pending_feedback_samples}</p>
                    <p className="text-xs text-slate-400 mt-1">Pending Samples</p>
                </div>
                <div className="bg-slate-800 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-slate-200">{status.total_feedback_in_db}</p>
                    <p className="text-xs text-slate-400 mt-1">Total Corrections</p>
                </div>
                <div className="bg-slate-800 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-orange-400">{status.total_false_positives}</p>
                    <p className="text-xs text-slate-400 mt-1">False Positives</p>
                </div>
            </div>

            {status.retrain_status.last_run && (
                <div className="bg-slate-800 rounded-lg p-3 mb-4 text-xs text-slate-400">
                    <p>Last retrain: {new Date(status.retrain_status.last_run).toLocaleString()}</p>
                    {status.retrain_status.last_result?.accuracy && (
                        <p className="text-green-400 mt-1">
                            Accuracy after retrain: {(status.retrain_status.last_result.accuracy * 100).toFixed(1)}%
                        </p>
                    )}
                </div>
            )}

            {result && (
                <div className={`rounded-lg p-3 mb-4 text-sm ${result.success ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                    {result.message}
                    {result.success && result.accuracy && (
                        <p className="mt-1 text-xs">
                            New accuracy: {(result.accuracy * 100).toFixed(1)}% ·
                            Trained on {result.total_samples} samples
                            ({result.feedback_samples} from analyst corrections)
                        </p>
                    )}
                </div>
            )}

            {isAdmin ? (
                <div>
                    {!status.ready_to_retrain && (
                        <p className="text-slate-500 text-xs mb-3">
                            Need {status.min_samples_required - status.pending_feedback_samples} more feedback
                            sample(s) before retraining is available.
                        </p>
                    )}
                    <Button
                        onClick={handleRetrain}
                        disabled={retraining || !status.ready_to_retrain || status.retrain_status.is_running}
                    >
                        {retraining || status.retrain_status.is_running
                            ? '⏳ Retraining...'
                            : `🔄 Retrain Model (${status.pending_feedback_samples} samples)`}
                    </Button>
                    <p className="text-xs text-slate-500 mt-2">
                        Retraining combines your original dataset + analyst corrections.
                        The model reloads automatically when done.
                    </p>
                </div>
            ) : (
                <p className="text-slate-500 text-xs">
                    Only admins can trigger model retraining. Submit corrections on emails to contribute.
                </p>
            )}
        </Card>
    )
}