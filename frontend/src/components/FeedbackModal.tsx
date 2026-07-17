import React, { useState } from 'react'
import { feedbackApi } from '../services/api'
import { Modal, Button, Badge } from '../components/common'

const LABELS = [
    { value: 'safe', label: 'Safe', color: 'green' },
    { value: 'bomb_threat', label: 'Bomb Threat', color: 'red' },
    { value: 'violence', label: 'Violence', color: 'red' },
    { value: 'terror', label: 'Terror', color: 'red' },
    { value: 'extortion', label: 'Extortion', color: 'orange' },
    { value: 'harassment', label: 'Harassment', color: 'orange' },
    { value: 'school_threat', label: 'School Threat', color: 'red' },
]

interface Props {
    emailId: number
    currentLabel: string
    onClose: () => void
    onSubmitted: () => void
}

export function FeedbackModal({ emailId, currentLabel, onClose, onSubmitted }: Props) {
    const [selectedLabel, setSelectedLabel] = useState(currentLabel)
    const [notes, setNotes] = useState('')
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState(false)

    const handleSubmit = async () => {
        if (selectedLabel === currentLabel) {
            setError('Please select a different label to submit a correction.')
            return
        }
        setLoading(true)
        setError('')
        try {
            await feedbackApi.submit(emailId, selectedLabel, notes || undefined)
            setSuccess(true)
            setTimeout(() => {
                onSubmitted()
                onClose()
            }, 1500)
        } catch (e: any) {
            setError(e.response?.data?.detail || 'Failed to submit feedback')
        } finally {
            setLoading(false)
        }
    }

    return (
        <Modal open={true} title="Correct ML Prediction" onClose={onClose}>
            <div className="space-y-5">
                {success ? (
                    <div className="text-center py-6">
                        <div className="text-4xl mb-3">✅</div>
                        <p className="text-green-400 font-medium">Feedback recorded!</p>
                        <p className="text-slate-400 text-sm mt-1">
                            This correction will be used in the next model retrain.
                        </p>
                    </div>
                ) : (
                    <>
                        <div>
                            <p className="text-slate-400 text-sm mb-1">Current prediction:</p>
                            <span className="inline-block px-3 py-1 rounded-full text-xs font-semibold bg-slate-700 text-slate-200">
                                {currentLabel.replace(/_/g, ' ')}
                            </span>
                        </div>

                        <div>
                            <p className="text-slate-300 text-sm font-medium mb-3">
                                What should this email be classified as?
                            </p>
                            <div className="grid grid-cols-2 gap-2">
                                {LABELS.map(label => (
                                    <button
                                        key={label.value}
                                        onClick={() => setSelectedLabel(label.value)}
                                        className={`px-3 py-2 rounded-lg text-sm font-medium border transition-all text-left ${selectedLabel === label.value
                                            ? 'border-blue-500 bg-blue-500/20 text-blue-300'
                                            : 'border-slate-600 bg-slate-800 text-slate-300 hover:border-slate-500'
                                            }`}
                                    >
                                        {label.label}
                                        {label.value === currentLabel && (
                                            <span className="ml-2 text-xs text-slate-500">(current)</span>
                                        )}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div>
                            <label className="text-slate-400 text-sm block mb-1">
                                Notes (optional)
                            </label>
                            <textarea
                                value={notes}
                                onChange={e => setNotes(e.target.value)}
                                placeholder="Why is this prediction wrong?"
                                rows={2}
                                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 resize-none"
                            />
                        </div>

                        {error && (
                            <p className="text-red-400 text-sm">{error}</p>
                        )}

                        <div className="flex gap-3 justify-end">
                            <Button variant="ghost" onClick={onClose} disabled={loading}>
                                Cancel
                            </Button>
                            <Button
                                onClick={handleSubmit}
                                disabled={loading || selectedLabel === currentLabel}
                            >
                                {loading ? 'Submitting...' : 'Submit Correction'}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Modal>
    )
}