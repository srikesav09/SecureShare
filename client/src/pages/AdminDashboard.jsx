import { useEffect, useState } from 'react';
import api from '../services/api';
import Icon from '../components/Icon';

function AdminDashboard({ notify, user }) {
  const [dashboard, setDashboard] = useState({ metrics: {}, recentLogs: [] });
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.get('/api/admin/dashboard'), api.get('/api/admin/users')])
      .then(([dashboardResponse, usersResponse]) => {
        setDashboard(dashboardResponse.data.data || { metrics: {}, recentLogs: [] });
        setUsers(usersResponse.data.data || []);
      })
      .catch((error) => notify(error.response?.data?.message || 'Could not load admin dashboard'))
      .finally(() => setLoading(false));
  }, [notify]);

  const toggleBlocked = async (target) => {
    try {
      const { data } = await api.patch(`/api/admin/users/${target.id}/block`, {
        blocked: !target.isBlocked,
      });

      setUsers((currentUsers) =>
        currentUsers.map((currentUser) => (currentUser.id === target.id ? data.data : currentUser)),
      );
      setDashboard((current) => ({
        ...current,
        metrics: {
          ...current.metrics,
          blockedUsers: Math.max(
            0,
            (current.metrics?.blockedUsers || 0) + (target.isBlocked ? -1 : 1),
          ),
        },
      }));
      notify(target.isBlocked ? 'User unblocked' : 'User blocked');
    } catch (error) {
      notify(error.response?.data?.message || 'Could not update user access');
    }
  };

  if (loading) return <div className="empty-section compact">Loading admin dashboard…</div>;

  return (
    <section className="admin-dashboard">
      <div className="stats-row">
        <div className="stat-card">
          <strong>{dashboard.metrics?.users || 0}</strong>
          <span>Users</span>
          <em>Registered accounts</em>
        </div>
        <div className="stat-card">
          <strong>{dashboard.metrics?.files || 0}</strong>
          <span>Files</span>
          <em>Encrypted objects</em>
        </div>
        <div className="stat-card">
          <strong>{dashboard.metrics?.blockedUsers || 0}</strong>
          <span>Blocked users</span>
          <em>Access restricted</em>
        </div>
        <div className="stat-card">
          <strong>{dashboard.metrics?.failedEvents || 0}</strong>
          <span>Failed events</span>
          <em>Review activity</em>
        </div>
      </div>
      <section className="panel page-panel">
        <div className="panel-heading">
          <div>
            <h2>User management</h2>
            <p>Restrict access for accounts that need review.</p>
          </div>
          <span className="status-chip">Protected</span>
        </div>
        <div className="admin-user-list">
          {users.map((target) => {
            const protectedAccount = target.role === 'ADMIN' || target.id === user?.id;

            return (
              <article className="admin-user-row" key={target.id}>
                <div className="admin-user-copy">
                  <strong>{target.name}</strong>
                  <small>{target.email}</small>
                  <details className="user-activity">
                    <summary>{target.recentLogs?.length || 0} recent user events</summary>
                    {target.recentLogs?.length ? (
                      <div className="user-activity-list">
                        {target.recentLogs.map((log) => (
                          <small key={log._id}>
                            {(log.action || 'UNKNOWN EVENT').replaceAll('_', ' ')} ·{' '}
                            {new Date(log.createdAt).toLocaleString()}
                          </small>
                        ))}
                      </div>
                    ) : (
                      <small>No activity recorded.</small>
                    )}
                  </details>
                </div>
                <span className={`user-status ${target.isBlocked ? 'blocked' : 'active'}`}>
                  {target.isBlocked ? 'Blocked' : 'Active'}
                </span>
                <button
                  className="button button-secondary button-small"
                  type="button"
                  disabled={protectedAccount}
                  onClick={() => toggleBlocked(target)}
                >
                  {protectedAccount ? 'Protected' : target.isBlocked ? 'Unblock' : 'Block'}
                </button>
              </article>
            );
          })}
        </div>
      </section>
      <section className="panel page-panel">
        <div className="panel-heading">
          <div>
            <h2>Recent security activity</h2>
            <p>Latest events across the vault.</p>
          </div>
          <span className="status-chip">Admin only</span>
        </div>
        {dashboard.recentLogs?.length ? (
          dashboard.recentLogs.map((log) => (
            <article className="audit-row" key={log._id}>
              <span className="audit-icon success">
                <Icon name="activity" size={17} />
              </span>
              <div className="audit-copy">
                <strong>{(log.action || 'UNKNOWN EVENT').replaceAll('_', ' ')}</strong>
                <small>{log.details?.filename || log.resourceType || 'Account activity'}</small>
              </div>
              <div className="audit-meta">
                <small>{new Date(log.createdAt).toLocaleString()}</small>
              </div>
            </article>
          ))
        ) : (
          <div className="empty-section compact">
            <Icon name="activity" size={28} />
            <h2>No recent activity</h2>
            <p>Security events will appear here.</p>
          </div>
        )}
      </section>
    </section>
  );
}

export default AdminDashboard;
