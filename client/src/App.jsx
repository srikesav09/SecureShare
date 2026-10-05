import { useEffect, useState } from 'react';
import api from './services/api';
import AuthPage from './pages/AuthPage';
import DashboardPage from './pages/DashboardPage';
import { SecureShareMark } from './components/Brand';
import './App.css';

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
      .catch(() => localStorage.removeItem('secureshare_token'))
      .finally(() => setChecking(false));
  }, []);

  const logout = () => {
    localStorage.removeItem('secureshare_token');
    setUser(null);
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

  return user ? (
    <DashboardPage user={user} onLogout={logout} />
  ) : (
    <AuthPage onAuthenticated={setUser} />
  );
}

export default App;
