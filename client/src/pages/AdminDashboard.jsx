import { useCallback, useEffect, useState } from 'react';
import api from '../services/api';
import Icon from '../components/Icon';

function AdminDashboard({ notify }) {
  const [data, setData] = useState({ metrics: {}, recentLogs: [] });
  const [queue, setQueue] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [dashboard, quarantine] = await Promise.all([
        api.get('/api/admin/dashboard'),
        api.get('/api/admin/quarantine'),
      ]);
      setData(dashboard.data.data);
      setQueue(quarantine.data.data || []);
    } catch (error) {
      notify(error.response?.data?.message || 'Could not load admin dashboard');
    } finally {
      setLoading(false);
    }
  }, [notify]);

  useEffect(() => {
    load();
  }, [load]);

  const release = async (fileId) => {
    try {
      await api.post(`/api/admin/quarantine/${fileId}/release`);
      notify('File released from quarantine');
      await load();
    } catch (error) {
      notify(error.response?.data?.message || 'Could not release file');
    }
  };

  if (loading) return <div className="empty-section compact">Loading admin controls…</div>;

  return (
    <section className="admin-dashboard">
      <div className="stats-row">
        <div className="stat-card">
          <strong>{data.metrics.users || 0}</strong>
          <span>Users</span>
          <em>Registered accounts</em>
        </div>
        <div className="stat-card">
          <strong>{data.metrics.files || 0}</strong>
          <span>Files</span>
          <em>Encrypted objects</em>
        </div>
        <div className="stat-card">
          <strong>{data.metrics.quarantined || 0}</strong>
          <span>Quarantined</span>
          <em className="security-warning">Needs review</em>
        </div>
      </div>
      <section className="panel page-panel">
        <div className="panel-heading">
          <div>
            <h2>Quarantine queue</h2>
            <p>Suspicious files are blocked from download and sharing until reviewed.</p>
          </div>
          <span className="status-chip">Admin only</span>
        </div>
        {queue.length ? (
          queue.map((file) => (
            <article className="quarantine-row" key={file.id}>
              <span className="settings-icon">
                <Icon name="alert" size={18} />
              </span>
              <div className="audit-copy">
                <strong>{file.originalName}</strong>
                <small>
                  {file.owner?.email || 'Unknown owner'} · Risk{' '}
                  {file.securityAnalysis?.riskScore || 0}/100
                </small>
              </div>
              <button className="secondary-button" onClick={() => release(file.id)}>
                Release after review
              </button>
            </article>
          ))
        ) : (
          <div className="empty-section compact">
            <Icon name="checkShield" size={28} />
            <h2>Queue is clear</h2>
            <p>No files are awaiting administrator review.</p>
          </div>
        )}
      </section>
      <section className="panel page-panel">
        <div className="panel-heading">
          <div>
            <h2>Recent security activity</h2>
            <p>Latest events across the vault.</p>
          </div>
        </div>
        <div className="audit-list">
          {data.recentLogs.map((log) => (
            <article className="audit-row" key={log._id}>
              <span className="audit-icon success">
                <Icon name="activity" size={17} />
              </span>
              <div className="audit-copy">
                <strong>{log.action.replaceAll('_', ' ')}</strong>
                <small>{log.details?.filename || log.resourceType || 'Account activity'}</small>
              </div>
              <div className="audit-meta">
                <small>{new Date(log.createdAt).toLocaleString()}</small>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}

export default AdminDashboard;
