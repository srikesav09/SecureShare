import { Component, useEffect, useState } from 'react';
import api from './services/api';
import AuthPage from './pages/AuthPage';
import DashboardPage from './pages/DashboardPage';
import { SecureShareMark } from './components/Brand';
import './App.css';

class AppErrorBoundary extends Component {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <main className="app-recovery-screen">
          <SecureShareMark />
          <h1>SecureShare could not open this page</h1>
          <p>Refresh the page after confirming that the API server is running.</p>
          <button className="primary-button" onClick={() => window.location.reload()}>
            Refresh SecureShare
          </button>
        </main>
      );
    }

    return this.props.children;
  }
}

function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('secureshare_token');
    if (!token) {
      setChecking(false);
      return undefined;
    }

    api
      .get('/api/auth/profile')
      .then(({ data }) => setUser(data.data))
      .catch(() => {
        localStorage.removeItem('secureshare_token');
        setUser(null);
      })
      .finally(() => setChecking(false));
  }, []);

  const logout = () => {
    api
      .post('/api/auth/logout')
      .catch(() => undefined)
      .finally(() => {
        localStorage.removeItem('secureshare_token');
        setUser(null);
      });
  };

  if (checking) {
    return (
      <div className="loading-screen">
        <span className="brand-mark">
          <SecureShareMark />
        </span>
        <p>Opening your secure vault…</p>
      </div>
    );
  }

  return (
    <AppErrorBoundary>
      {user ? (
        <DashboardPage user={user} onLogout={logout} />
      ) : (
        <AuthPage onAuthenticated={setUser} />
      )}
    </AppErrorBoundary>
  );
}

export default App;
