import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import api, { API_ORIGIN } from '../services/api';
import { appRoutes } from '../routes/routeConfig';
import { Brand } from '../components/Brand';
import Icon from '../components/Icon';
import FileList from '../components/FileList';
import { formatBytes } from '../services/formatters';

function ShareModal({ target, onClose, onCreated, notify }) {
  const [options, setOptions] = useState({ maxDownloads: '', password: '', expiresInHours: '24' });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const createShare = async (event) => {
    event.preventDefault();
    setLoading(true);
    try {
      const { data } = await api.post(`/api/share/${target.id}`, {
        maxDownloads: options.maxDownloads ? Number(options.maxDownloads) : null,
        password: options.password || null,
        expiresInHours: Number(options.expiresInHours),
      });
      const share = data.data || data;
      setResult(share);
      onCreated({ ...share, fileName: target.originalName });
      notify('Share link created');
    } catch (error) {
      notify(error.response?.data?.message || 'Couldn’t create share link');
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(result.shareLink);
      notify('Share link copied');
    } catch {
      notify('Copy failed. Select the link manually.');
    }
  };

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
    >
      <section
        className="share-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="share-title"
      >
        <button className="modal-close" aria-label="Close" onClick={onClose}>
          <Icon name="close" size={18} />
        </button>
        <span className="settings-icon">
          <Icon name="link" size={22} />
        </span>
        <h2 id="share-title">Share {target.originalName}</h2>
        {result ? (
          <div className="share-result">
            <p>Your secure link is ready and expires in {options.expiresInHours} hours.</p>
            <div className="share-link-box">{result.shareLink}</div>
            <button className="primary-button full" onClick={copy}>
              <Icon name="copy" size={16} /> Copy link
            </button>
            <button className="text-button modal-secondary" onClick={onClose}>
              Done
            </button>
          </div>
        ) : (
          <form className="share-form" onSubmit={createShare}>
            <p>
              Set optional controls for this link. Leave them blank for a standard 24-hour link.
            </p>
            <label>
              Download limit
              <input
                type="number"
                min="1"
                value={options.maxDownloads}
                onChange={(event) => setOptions({ ...options, maxDownloads: event.target.value })}
                placeholder="Unlimited"
              />
            </label>
            <label>
              Link password
              <input
                type="password"
                minLength="8"
                value={options.password}
                onChange={(event) => setOptions({ ...options, password: event.target.value })}
                placeholder="Optional, 8+ characters"
              />
            </label>
            <label>
              Link expiration
              <select
                value={options.expiresInHours}
                onChange={(event) => setOptions({ ...options, expiresInHours: event.target.value })}
              >
                <option value="1">1 hour</option>
                <option value="6">6 hours</option>
                <option value="24">24 hours</option>
                <option value="72">3 days</option>
                <option value="168">7 days</option>
              </select>
            </label>
            <button className="primary-button full" disabled={loading}>
              {loading ? 'Creating link…' : 'Create secure link'}
            </button>
          </form>
        )}
      </section>
    </div>
  );
}

function PreviewModal({ file, url, onClose, onDownload }) {
  const mimeType = file.mimeType || 'application/octet-stream';
  const isImage = mimeType.startsWith('image/');
  const isVideo = mimeType.startsWith('video/');
  const isAudio = mimeType.startsWith('audio/');
  const isPdf = mimeType === 'application/pdf';

  return (
    <div
      className="modal-backdrop preview-backdrop"
      role="presentation"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
    >
      <section
        className="preview-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="preview-title"
      >
        <div className="preview-header">
          <div>
            <span className="eyebrow">File preview</span>
            <h2 id="preview-title">{file.originalName}</h2>
          </div>
          <button className="modal-close" aria-label="Close preview" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="preview-content">
          {isImage && <img src={url} alt={file.originalName} className="preview-media" />}
          {isVideo && <video src={url} className="preview-media" controls />}
          {isAudio && <audio src={url} className="preview-audio" controls />}
          {isPdf && (
            <iframe src={url} title={`Preview of ${file.originalName}`} className="preview-frame" />
          )}
          {!isImage && !isVideo && !isAudio && !isPdf && (
            <div className="preview-unavailable">
              <Icon name="file" size={30} />
              <strong>This file type cannot be previewed in the browser.</strong>
              <p>Download it to open it with the appropriate application.</p>
            </div>
          )}
        </div>
        <div className="preview-footer">
          <span>{mimeType}</span>
          <button className="secondary-button" onClick={() => onDownload(file)}>
            <Icon name="download" size={16} /> Download
          </button>
        </div>
      </section>
    </div>
  );
}

function DashboardPage({ user, onLogout }) {
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [toast, setToast] = useState('');
  const [shareTarget, setShareTarget] = useState(null);
  const [previewState, setPreviewState] = useState(null);
  const [sessionShares, setSessionShares] = useState([]);
  const [search, setSearch] = useState('');
  const [theme, setTheme] = useState(() => localStorage.getItem('secureshare_theme') || 'light');
  const [profilePhoto, setProfilePhoto] = useState(
    () => localStorage.getItem('secureshare_profile_photo') || '',
  );
  const [importForm, setImportForm] = useState({ shareLink: '', password: '' });
  const [importState, setImportState] = useState({ loading: false, message: '', success: false });
  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '' });
  const [passwordState, setPasswordState] = useState({
    loading: false,
    message: '',
    success: false,
  });
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
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

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute('content', theme === 'dark' ? '#10201f' : '#39746d');
    localStorage.setItem('secureshare_theme', theme);
  }, [theme]);

  useEffect(() => {
    return () => {
      if (previewState) URL.revokeObjectURL(previewState.url);
    };
  }, [previewState]);

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
      await loadFiles();
    } catch (error) {
      notify(error.response?.data?.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const download = async (file, preview = false) => {
    try {
      const response = await api.get(`/api/files/${file.id}/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      if (preview) {
        setPreviewState((current) => {
          if (current) URL.revokeObjectURL(current.url);
          return { file, url };
        });
      } else {
        const link = document.createElement('a');
        link.href = url;
        link.download = file.originalName;
        link.click();
        URL.revokeObjectURL(url);
      }
    } catch {
      notify(preview ? 'Couldn’t preview that file' : 'Couldn’t download that file');
    }
  };

  const closePreview = () => {
    if (previewState) URL.revokeObjectURL(previewState.url);
    setPreviewState(null);
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
  const storageLimit = user?.storageLimit || 100 * 1024 * 1024;
  const usedPercent = Math.min(100, Math.round((used / storageLimit) * 100));
  const visibleFiles = files.filter((file) =>
    file.originalName.toLowerCase().includes(search.trim().toLowerCase()),
  );
  const fileActions = {
    onPreview: (file) => download(file, true),
    onDownload: download,
    onShare: setShareTarget,
    onDelete: remove,
  };

  const changePassword = async (event) => {
    event.preventDefault();
    setPasswordState({ loading: true, message: '', success: false });
    try {
      const { data } = await api.patch('/api/auth/password', passwordForm);
      setPasswordState({
        loading: false,
        message: data.message || 'Password changed successfully.',
        success: true,
      });
      setPasswordForm({ currentPassword: '', newPassword: '' });
      setShowCurrentPassword(false);
      setShowNewPassword(false);
    } catch (error) {
      setPasswordState({
        loading: false,
        message: error.response?.data?.message || 'Couldn’t change password.',
        success: false,
      });
    }
  };

  const importSharedFile = async (event) => {
    event.preventDefault();
    setImportState({ loading: true, message: '', success: false });
    try {
      const { data } = await api.post('/api/files/import-share', importForm);
      setImportForm({ shareLink: '', password: '' });
      setImportState({
        loading: false,
        message: data.message || 'File saved to your vault.',
        success: true,
      });
      await loadFiles();
      notify('Shared file saved to your vault');
    } catch (error) {
      setImportState({
        loading: false,
        message: error.response?.data?.message || 'Couldn’t save this shared file.',
        success: false,
      });
    }
  };

  const chooseProfilePhoto = (event) => {
    const [file] = event.target.files || [];
    if (!file || !file.type.startsWith('image/')) return;
    if (file.size > 2 * 1024 * 1024) {
      notify('Profile photo must be smaller than 2 MB');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setProfilePhoto(reader.result);
      localStorage.setItem('secureshare_profile_photo', reader.result);
    };
    reader.readAsDataURL(file);
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav>
          {appRoutes.map((item) => (
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
      </aside>
      <section className="workspace">
        <header className="topbar">
          <label className="nav-search topbar-search">
            <span className="sr-only">Search files</span>
            <Icon name="search" size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  navigate('/files');
                }
              }}
              placeholder="Search files"
            />
          </label>
          <div className="user-menu">
            <div className="storage-indicator" title="Storage used">
              <span>Storage</span>
              <strong>
                {formatBytes(used)} / {formatBytes(storageLimit)}
              </strong>
              <i>
                <b style={{ width: `${Math.max(2, usedPercent)}%` }} />
              </i>
            </div>
            <button
              className="theme-toggle"
              aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
              aria-pressed={theme === 'dark'}
              title={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
              onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
            >
              <Icon name={theme === 'light' ? 'sun' : 'moon'} size={16} />
            </button>
            <label className="profile-trigger" title="Choose profile photo">
              {profilePhoto ? (
                <img src={profilePhoto} alt="Profile" />
              ) : (
                <span className="avatar">{user?.name?.slice(0, 2).toUpperCase() || 'SM'}</span>
              )}
              <input type="file" accept="image/*" hidden onChange={chooseProfilePhoto} />
            </label>
            <span className="user-name">{user?.name || 'Srikesav'}</span>
            <button
              className="settings-shortcut"
              onClick={() => navigate('/settings')}
              aria-label="Open settings"
            >
              <Icon name="settings" size={16} />
            </button>
            <a
              className="help-link"
              href="https://github.com/srikesav09"
              target="_blank"
              rel="noreferrer"
            >
              Need help? ↗
            </a>
            <button className="sign-out" onClick={onLogout}>
              Sign out
            </button>
          </div>
        </header>
        <div className="content">
          <div className="page-heading">
            <div>
              <h1>
                {active === 'Overview'
                  ? `Good afternoon, ${user?.name?.split(' ')[0] || 'Srikesav'}`
                  : active}
              </h1>
              <p>
                {active === 'Overview'
                  ? 'Everything important, protected in one place.'
                  : 'Keep your files protected and under your control.'}
              </p>
            </div>
            <div className="heading-actions">
              <button className="primary-button" onClick={() => inputRef.current?.click()}>
                <Icon name="upload" size={17} /> Upload a file
              </button>
            </div>
          </div>
          <input
            ref={inputRef}
            type="file"
            hidden
            onChange={(event) => upload(event.target.files?.[0])}
          />
          {active === 'My files' ? (
            <section className="panel page-panel">
              <div className="panel-heading">
                <div>
                  <h2>All files</h2>
                  <p>Manage every encrypted file in your vault.</p>
                </div>
              </div>
              <FileList files={visibleFiles} {...fileActions} />
            </section>
          ) : active === 'Shared links' ? (
            <section className="panel page-panel">
              <div className="panel-heading">
                <div>
                  <h2>Shared links</h2>
                  <p>Links created during this session appear here.</p>
                </div>
                <span className="status-chip">Configurable expiry</span>
              </div>
              <form className="import-share-card" onSubmit={importSharedFile}>
                <div className="share-row-icon">
                  <Icon name="download" size={17} />
                </div>
                <div className="import-share-copy">
                  <strong>Save a shared file to your vault</strong>
                  <small>
                    Paste a SecureShare link to save a copy without downloading it to your device.
                  </small>
                </div>
                <div className="import-share-fields">
                  <input
                    required
                    type="url"
                    placeholder={`${API_ORIGIN}/share/...`}
                    value={importForm.shareLink}
                    onChange={(event) =>
                      setImportForm({ ...importForm, shareLink: event.target.value })
                    }
                  />
                  <input
                    type="password"
                    placeholder="Link password (if required)"
                    value={importForm.password}
                    onChange={(event) =>
                      setImportForm({ ...importForm, password: event.target.value })
                    }
                  />
                  <button className="primary-button" disabled={importState.loading}>
                    {importState.loading ? 'Saving…' : 'Save to vault'}
                  </button>
                </div>
                {importState.message && (
                  <div className={`form-message ${importState.success ? 'success' : ''}`}>
                    {importState.message}
                  </div>
                )}
              </form>
              {sessionShares.length ? (
                <div className="share-list">
                  {sessionShares.map((share) => (
                    <div className="share-row" key={share.shareId}>
                      <span className="share-row-icon">
                        <Icon name="link" size={17} />
                      </span>
                      <div>
                        <strong>{share.fileName}</strong>
                        <small>{share.shareLink}</small>
                      </div>
                      <button
                        className="icon-button"
                        title="Copy share link"
                        onClick={() => navigator.clipboard.writeText(share.shareLink)}
                      >
                        <Icon name="copy" size={17} />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-section compact">
                  <div className="empty-icon">
                    <Icon name="link" size={26} />
                  </div>
                  <h2>No active links yet</h2>
                  <p>Choose the link icon on any file to create a secure share link.</p>
                  <button className="secondary-button" onClick={() => navigate('/files')}>
                    Browse my files
                  </button>
                </div>
              )}
            </section>
          ) : active === 'Settings' ? (
            <section className="settings-grid">
              <div className="panel settings-card">
                <span className="settings-icon">
                  <Icon name="shield" size={22} />
                </span>
                <h2>Account security</h2>
                <p>
                  Your account is protected with token-based authentication and encrypted file
                  storage.
                </p>
                <div className="settings-line">
                  <span>Signed in as</span>
                  <strong>{user?.email}</strong>
                </div>
                <div className="settings-line">
                  <span>Vault protection</span>
                  <strong className="security-good">Active</strong>
                </div>
              </div>
              <div className="panel settings-card">
                <span className="settings-icon">
                  <Icon name="settings" size={22} />
                </span>
                <h2>Workspace preferences</h2>
                <p>
                  Share links can expire from 1 hour to 7 days and can be protected with a password.
                </p>
                <div className="settings-line">
                  <span>Storage limit</span>
                  <strong>{formatBytes(storageLimit)}</strong>
                </div>
                <div className="settings-line">
                  <span>API status</span>
                  <strong className="security-good">Connected</strong>
                </div>
              </div>
              <div className="panel settings-card security-settings">
                <span className="settings-icon">
                  <Icon name="shield" size={22} />
                </span>
                <h2>Change password</h2>
                <p>Use a strong, unique password to keep your vault protected.</p>
                <form className="password-form" onSubmit={changePassword}>
                  <label>
                    Current password
                    <span className="password-input">
                      <input
                        type={showCurrentPassword ? 'text' : 'password'}
                        required
                        value={passwordForm.currentPassword}
                        onChange={(event) =>
                          setPasswordForm({ ...passwordForm, currentPassword: event.target.value })
                        }
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                        aria-label="Show current password"
                      >
                        <Icon name="eye" size={17} />
                      </button>
                    </span>
                  </label>
                  <label>
                    New password
                    <span className="password-input">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        required
                        minLength="8"
                        value={passwordForm.newPassword}
                        onChange={(event) =>
                          setPasswordForm({ ...passwordForm, newPassword: event.target.value })
                        }
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        aria-label="Show new password"
                      >
                        <Icon name="eye" size={17} />
                      </button>
                    </span>
                  </label>
                  <small className="password-hint">
                    At least 8 characters. Avoid reusing another password.
                  </small>
                  {passwordState.message && (
                    <div className={`form-message ${passwordState.success ? 'success' : ''}`}>
                      {passwordState.message}
                    </div>
                  )}
                  <button className="primary-button" disabled={passwordState.loading}>
                    {passwordState.loading ? 'Updating…' : 'Update password'}
                  </button>
                </form>
              </div>
            </section>
          ) : (
            <Overview
              files={files}
              used={used}
              usedPercent={usedPercent}
              uploading={uploading}
              dragging={dragging}
              setDragging={setDragging}
              upload={upload}
              inputRef={inputRef}
              navigate={navigate}
              fileActions={fileActions}
            />
          )}
        </div>
      </section>
      {toast && (
        <div className="toast">
          <Icon name="check" size={16} />
          {toast}
        </div>
      )}
      {previewState && (
        <PreviewModal
          file={previewState.file}
          url={previewState.url}
          onClose={closePreview}
          onDownload={download}
        />
      )}
      {shareTarget && (
        <ShareModal
          target={shareTarget}
          onClose={() => setShareTarget(null)}
          onCreated={(share) => setSessionShares((current) => [share, ...current])}
          notify={notify}
        />
      )}
    </main>
  );
}

function Overview({
  files,
  used,
  usedPercent,
  uploading,
  dragging,
  setDragging,
  upload,
  inputRef,
  navigate,
  fileActions,
}) {
  return (
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
          <strong>{uploading ? 'Encrypting and uploading…' : 'Drop files here to upload'}</strong>
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
            <button className="text-button" onClick={() => navigate('/files')}>
              View all
            </button>
          </div>
          <FileList files={files} {...fileActions} />
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
  );
}

export default DashboardPage;
