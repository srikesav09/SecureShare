import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import api from './services/api';
import './App.css';
import { appRoutes } from './routes/routeConfig';

const formatBytes = (bytes = 0) => {
  if (!bytes) return '0 KB';
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDate = (date) =>
  new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(date));

function Icon({ name, size = 18 }) {
  const paths = {
    grid: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
    upload: 'M12 16V4m0 0L7 9m5-5 5 5M5 20h14',
    share:
      'M18 8a3 3 0 1 0-2.83-4A3 3 0 0 0 15 5c0 .34.06.66.16.96L8.84 9.5A3 3 0 0 0 7 9a3 3 0 1 0 1.84 5.5l6.32 3.54A3 3 0 1 0 17 16c-.34 0-.66.06-.96.16l-6.32-3.54c.18-.5.28-1.05.28-1.62s-.1-1.12-.28-1.62l6.32-3.54c.3.1.62.16.96.16Z',
    settings:
      'M12 15.4a3.4 3.4 0 1 0 0-6.8 3.4 3.4 0 0 0 0 6.8Zm0-12v2m0 13.2v2M4.44 4.44l1.42 1.42m12.28 12.28 1.42 1.42M2 12h2m16 0h2M4.44 19.56l1.42-1.42M18.14 5.86l1.42-1.42',
    download: 'M12 4v11m0 0 5-5m-5 5-5-5M5 20h14',
    eye: 'M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Zm9.5 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
    trash: 'M5 7h14m-9 4v5m4-5v5M9 7V4h6v3m-8 0 1 13h8l1-13',
    check: 'm5 12 4 4L19 6',
  };
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={paths[name]} />
    </svg>
  );
}

function SecureShareMark({ size = 36 }) {
  return (
    <svg
      className="secure-share-mark"
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
    >
      <rect width="48" height="48" rx="14" fill="currentColor" />
      <path
        d="M24 10.5 35 15v8.7c0 7.2-4.7 11.9-11 14.8-6.3-2.9-11-7.6-11-14.8V15l11-4.5Z"
        fill="white"
        fillOpacity=".96"
      />
      <path d="M24 17v13m-5-5.5h10" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" />
      <circle cx="24" cy="24" r="2.4" fill="currentColor" />
      <path
        d="m28.2 19.4 2.8-2.8m0 0v2.3m0-2.3h-2.3"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <SecureShareMark />
      </span>
      <span>SecureShare</span>
    </div>
  );
}

function AuthScreen({ onAuthenticated }) {
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [state, setState] = useState({
    loading: false,
    message: '',
    success: false,
  });
  const update = (key) => (event) =>
    setForm((current) => ({ ...current, [key]: event.target.value }));
  const submit = async (event) => {
    event.preventDefault();
    setState({ loading: true, message: '', success: false });
    try {
      const { data } = await api.post(`/api/auth/${mode === 'login' ? 'login' : 'register'}`, form);
      if (mode === 'login') {
        localStorage.setItem('secureshare_token', data.data.token);
        onAuthenticated(data.data.user);
      } else {
        setMode('login');
        setState({
          loading: false,
          message: 'Account created. Sign in to continue.',
          success: true,
        });
      }
    } catch (error) {
      setState({
        loading: false,
        message:
          error.response?.data?.message ||
          (!error.response
            ? 'SecureShare API is unavailable. Start the server on port 5000 and try again.'
            : 'We couldn’t complete that request.'),
        success: false,
      });
    }
  };
  return (
    <main className="auth-shell">
      <section className="auth-art">
        <Brand />
        <div className="auth-copy">
          <span className="eyebrow">PRIVATE BY DESIGN</span>
          <h1>Share with confidence.</h1>
          <p>Your files are encrypted before they leave your device, so your work stays yours.</p>
          <div className="trust-list">
            <span>
              <Icon name="check" size={16} /> End-to-end encryption
            </span>
            <span>
              <Icon name="check" size={16} /> Expiring share links
            </span>
            <span>
              <Icon name="check" size={16} /> Full ownership control
            </span>
          </div>
        </div>
        <div className="art-glow" />
      </section>
      <section className="auth-panel">
        <div className="auth-card">
          <div className="auth-heading">
            <span className="eyebrow">WELCOME BACK</span>
            <h2>{mode === 'login' ? 'Sign in to your vault' : 'Create your vault'}</h2>
            <p>
              {mode === 'login'
                ? 'Pick up where you left off.'
                : 'A safer home for your important files.'}
            </p>
          </div>
          <form onSubmit={submit}>
            {mode === 'register' && (
              <label>
                Full name
                <input
                  required
                  value={form.name}
                  onChange={update('name')}
                  placeholder="Srikesav M"
                />
              </label>
            )}
            <label>
              Email address
              <input
                required
                type="email"
                value={form.email}
                onChange={update('email')}
                placeholder="you@example.com"
              />
            </label>
            <label>
              Password
              <input
                required
                minLength={8}
                type="password"
                value={form.password}
                onChange={update('password')}
                placeholder="At least 8 characters"
              />
            </label>
            {state.message && (
              <div className={`form-message ${state.success ? 'success' : ''}`}>
                {state.message}
              </div>
            )}
            <button className="primary-button full" disabled={state.loading}>
              {state.loading
                ? 'Working…'
                : mode === 'login'
                  ? 'Enter SecureShare'
                  : 'Create account'}
            </button>
          </form>
          <p className="switch-auth">
            {mode === 'login' ? 'New to SecureShare?' : 'Already have an account?'}{' '}
            <button
              onClick={() => {
                setMode(mode === 'login' ? 'register' : 'login');
                setState({ loading: false, message: '', success: false });
              }}
            >
              {mode === 'login' ? 'Create an account' : 'Sign in'}
            </button>
          </p>
        </div>
      </section>
    </main>
  );
}

function Dashboard({ user, onLogout }) {
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [toast, setToast] = useState('');
  const active = appRoutes.find((item) => item.path === location.pathname)?.name || 'Overview';
  const loadFiles = useCallback(async () => {
    try {
      const { data } = await api.get('/api/files');
      setFiles(data.data || []);
    } catch (error) {
      if (error.response?.status === 401) onLogout();
    }
  }, [onLogout]);
  useEffect(() => {
    loadFiles();
  }, [loadFiles]);
  const notify = (message) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 4000);
  };
  const upload = async (file) => {
    if (!file) return;
    setUploading(true);
    const body = new FormData();
    body.append('file', file);
    try {
      await api.post('/api/files/upload', body);
      notify('File encrypted and uploaded');
      loadFiles();
    } catch (error) {
      notify(error.response?.data?.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };
  const download = async (file) => {
    try {
      const response = await api.get(`/api/files/${file.id}/download`, {
        responseType: 'blob',
      });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.originalName;
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      notify('Couldn’t download that file');
    }
  };
  const viewFile = async (file) => {
    try {
      const response = await api.get(`/api/files/${file.id}/download`, {
        responseType: 'blob',
      });
      const url = URL.createObjectURL(response.data);
      const preview = window.open(url, '_blank', 'noopener,noreferrer');
      if (!preview) notify('Allow pop-ups to preview this file');
      window.setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch {
      notify('Couldn’t preview that file');
    }
  };
  const remove = async (file) => {
    if (!window.confirm(`Delete ${file.originalName}?`)) return;
    try {
      await api.delete(`/api/files/${file.id}`);
      setFiles((current) => current.filter((item) => item.id !== file.id));
      notify('File deleted');
    } catch {
      notify('Couldn’t delete that file');
    }
  };
  const used = files.reduce((total, file) => total + (file.size || 0), 0);
  const usedPercent = Math.min(100, Math.round((used / (10 * 1024 * 1024 * 1024)) * 100));
  const nav = appRoutes;
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav>
          {nav.map((item) => (
            <button
              key={item.name}
              className={active === item.name ? 'nav-item active' : 'nav-item'}
              onClick={() => navigate(item.path)}
            >
              <Icon name={item.icon} />
              {item.name}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span>Need help?</span>
          <a href="https://github.com/srikesav09/SecureShare" target="_blank" rel="noreferrer">
            Read the security guide ↗
          </a>
        </div>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <span className="date-label">Tuesday, September 15, 2026</span>
          <div className="user-menu">
            <span className="avatar">{user?.name?.slice(0, 2).toUpperCase() || 'SM'}</span>
            <span className="user-name">{user?.name || 'Srikesav'}</span>
            <button className="sign-out" onClick={onLogout}>
              Sign out
            </button>
          </div>
        </header>
        <div className="content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">YOUR PRIVATE WORKSPACE</span>
              <h1>Good afternoon, {user?.name?.split(' ')[0] || 'Srikesav'}</h1>
              <p>Everything important, protected in one place.</p>
            </div>
            <button className="primary-button" onClick={() => inputRef.current?.click()}>
              <Icon name="upload" size={17} /> Upload a file
            </button>
          </div>
          {active !== 'Overview' ? (
            <div className="empty-section">
              <div className="empty-icon">
                <Icon name={nav.find((item) => item.name === active)?.icon || 'grid'} size={28} />
              </div>
              <h2>{active}</h2>
              <p>
                This workspace is ready for the next step. Your core file workflow is available from
                Overview.
              </p>
              <button className="secondary-button" onClick={() => navigate('/')}>
                Back to overview
              </button>
            </div>
          ) : (
            <>
              <div className="stats-row">
                <div className="stat-card">
                  <strong>{files.length}</strong>
                  <span>Files stored</span>
                  <em>{files.length ? 'Up to date' : 'Start with your first file'}</em>
                </div>
                <div className="stat-card">
                  <strong>{formatBytes(used)}</strong>
                  <span>Storage used</span>
                  <em>of 10 GB</em>
                </div>
                <div className="stat-card">
                  <strong>{files.length ? 'Protected' : 'Ready'}</strong>
                  <span>Vault status</span>
                  <em className="green">All systems secure</em>
                </div>
              </div>
              <input
                ref={inputRef}
                type="file"
                hidden
                onChange={(event) => upload(event.target.files?.[0])}
              />
              <button
                className={`drop-zone ${dragging ? 'dragging' : ''}`}
                onClick={() => inputRef.current?.click()}
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault();
                  setDragging(false);
                  upload(event.dataTransfer.files?.[0]);
                }}
              >
                <span className="drop-icon">
                  <Icon name="upload" size={24} />
                </span>
                <span>
                  <strong>
                    {uploading ? 'Encrypting and uploading…' : 'Drop files here to upload'}
                  </strong>
                  <small>or browse from your computer</small>
                  <small>Encrypted before it leaves your device · Max 50 MB</small>
                </span>
                <span className="browse-pill">Browse files</span>
              </button>
              <div className="dashboard-grid">
                <section className="panel files-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Recent files</h2>
                      <p>Your latest encrypted uploads</p>
                    </div>
                    <button className="text-button">View all</button>
                  </div>
                  {files.length ? (
                    <div className="file-list">
                      {files.map((file) => (
                        <div className="file-row" key={file.id}>
                          <div className="file-type">
                            {file.mimeType?.split('/')[1]?.slice(0, 3).toUpperCase() || 'FILE'}
                          </div>
                          <div className="file-name">
                            <strong>{file.originalName}</strong>
                            <small>{formatDate(file.createdAt)}</small>
                          </div>
                          <span className="file-size">{formatBytes(file.size)}</span>
                          <div className="file-actions">
                            <button aria-label="Preview file" onClick={() => viewFile(file)}>
                              <Icon name="eye" size={17} />
                            </button>
                            <button aria-label="Download" onClick={() => download(file)}>
                              <Icon name="download" size={17} />
                            </button>
                            <button aria-label="Delete" onClick={() => remove(file)}>
                              <Icon name="trash" size={17} />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-files">
                      <div className="empty-file-icon">
                        <Icon name="upload" size={20} />
                      </div>
                      <strong>Your vault is empty</strong>
                      <p>Upload your first file to see it here.</p>
                    </div>
                  )}
                </section>
                <aside className="panel health-panel">
                  <h2>Storage health</h2>
                  <p>Your vault is running smoothly.</p>
                  <div className="meter">
                    <span style={{ width: `${Math.max(8, 100 - usedPercent)}%` }} />
                  </div>
                  <div className="health-meta">
                    <strong>{100 - usedPercent}% available</strong>
                    <span>Protected by encryption</span>
                  </div>
                  <div className="share-callout">
                    <span className="share-callout-icon">
                      <Icon name="share" size={21} />
                    </span>
                    <strong>Share safely</strong>
                    <p>Create links that expire automatically and can be revoked anytime.</p>
                  </div>
                </aside>
              </div>
            </>
          )}
        </div>
      </section>
      {toast && (
        <div className="toast">
          <Icon name="check" size={16} />
          {toast}
        </div>
      )}
    </main>
  );
}

function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);
  useEffect(() => {
    const token = localStorage.getItem('secureshare_token');
    if (!token) {
      setChecking(false);
      return;
    }
    api
      .get('/api/auth/profile')
      .then(({ data }) => setUser(data.data))
      .catch(() => localStorage.removeItem('secureshare_token'))
      .finally(() => setChecking(false));
  }, []);
  const logout = () => {
    localStorage.removeItem('secureshare_token');
    setUser(null);
  };
  if (checking)
    return (
      <div className="loading-screen">
        <span className="brand-mark">
          <SecureShareMark />
        </span>
        <p>Opening your secure vault…</p>
      </div>
    );
  return user ? (
    <Dashboard user={user} onLogout={logout} />
  ) : (
    <AuthScreen onAuthenticated={setUser} />
  );
}

export default App;
