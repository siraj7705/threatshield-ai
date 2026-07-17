// =========================================================
// LOCATION: threatshield-ai/frontend/src/pages/UsersPage.tsx
// =========================================================
import { useEffect, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000";

interface User {
    id: number;
    username: string;
    email: string;
    full_name: string | null;
    role: string;
    is_active: boolean;
    created_at: string;
    last_login: string | null;
}

const ROLE_COLORS: Record<string, string> = {
    admin: "bg-red-500/20 text-red-400 border border-red-500/30",
    analyst: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
    investigator: "bg-purple-500/20 text-purple-400 border border-purple-500/30",
};

export default function UsersPage() {
    const [users, setUsers] = useState<User[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const token = localStorage.getItem("access_token");
    const headers = { Authorization: `Bearer ${token}` };

    const fetchUsers = async () => {
        try {
            setLoading(true);
            const res = await axios.get(`${API}/api/users`, { headers });
            setUsers(res.data.users);
        } catch (e: any) {
            setError(e.response?.data?.detail || "Failed to load users");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchUsers(); }, []);

    const updateRole = async (userId: number, role: string) => {
        try {
            await axios.patch(`${API}/api/users/${userId}/role`, { role }, { headers });
            fetchUsers();
        } catch (e: any) {
            alert(e.response?.data?.detail || "Failed to update role");
        }
    };

    const toggleStatus = async (user: User) => {
        try {
            await axios.patch(
                `${API}/api/users/${user.id}/status`,
                { is_active: !user.is_active },
                { headers }
            );
            fetchUsers();
        } catch (e: any) {
            alert(e.response?.data?.detail || "Failed to update status");
        }
    };

    const deleteUser = async (user: User) => {
        if (!confirm(`Delete user "${user.username}"? This cannot be undone.`)) return;
        try {
            await axios.delete(`${API}/api/users/${user.id}`, { headers });
            fetchUsers();
        } catch (e: any) {
            alert(e.response?.data?.detail || "Failed to delete user");
        }
    };

    if (loading) return (
        <div className="flex items-center justify-center h-64">
            <div className="text-slate-400">Loading users...</div>
        </div>
    );

    if (error) return (
        <div className="p-6 text-red-400 bg-red-500/10 rounded-lg border border-red-500/20">
            {error} — You may not have admin access.
        </div>
    );

    return (
        <div className="p-6">
            <div className="mb-6">
                <h1 className="text-2xl font-bold text-white">User Management</h1>
                <p className="text-slate-400 mt-1">Manage roles and access for all platform users. Admin only.</p>
            </div>

            <div className="bg-slate-900 rounded-xl border border-slate-700 overflow-hidden">
                <table className="w-full">
                    <thead>
                        <tr className="border-b border-slate-700 text-left">
                            <th className="px-4 py-3 text-slate-400 text-sm font-medium">User</th>
                            <th className="px-4 py-3 text-slate-400 text-sm font-medium">Role</th>
                            <th className="px-4 py-3 text-slate-400 text-sm font-medium">Status</th>
                            <th className="px-4 py-3 text-slate-400 text-sm font-medium">Last Login</th>
                            <th className="px-4 py-3 text-slate-400 text-sm font-medium">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map((user) => (
                            <tr key={user.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                                <td className="px-4 py-3">
                                    <div className="text-white font-medium">{user.username}</div>
                                    <div className="text-slate-400 text-sm">{user.email}</div>
                                </td>
                                <td className="px-4 py-3">
                                    <select
                                        value={user.role}
                                        onChange={(e) => updateRole(user.id, e.target.value)}
                                        className={`text-xs px-2 py-1 rounded-full font-medium bg-transparent cursor-pointer ${ROLE_COLORS[user.role]}`}
                                    >
                                        <option value="admin">admin</option>
                                        <option value="analyst">analyst</option>
                                        <option value="investigator">investigator</option>
                                    </select>
                                </td>
                                <td className="px-4 py-3">
                                    <span className={`text-xs px-2 py-1 rounded-full font-medium ${user.is_active
                                            ? "bg-green-500/20 text-green-400 border border-green-500/30"
                                            : "bg-slate-600/20 text-slate-400 border border-slate-600/30"
                                        }`}>
                                        {user.is_active ? "Active" : "Inactive"}
                                    </span>
                                </td>
                                <td className="px-4 py-3 text-slate-400 text-sm">
                                    {user.last_login
                                        ? new Date(user.last_login).toLocaleDateString()
                                        : "Never"}
                                </td>
                                <td className="px-4 py-3">
                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => toggleStatus(user)}
                                            className="text-xs px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 transition"
                                        >
                                            {user.is_active ? "Deactivate" : "Activate"}
                                        </button>
                                        <button
                                            onClick={() => deleteUser(user)}
                                            className="text-xs px-3 py-1 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition"
                                        >
                                            Delete
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {users.length === 0 && (
                    <div className="text-center py-12 text-slate-400">No users found.</div>
                )}
            </div>
        </div>
    );
}