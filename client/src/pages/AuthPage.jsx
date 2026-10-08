import { useState } from 'react';
import api from '../services/api';
import Icon from '../components/Icon';
import { Brand } from '../components/Brand';

function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [state, setState] = useState({ loading: false, message: '', success: false });
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
          message: 'Account created. Sign-in to continue.',
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
            <span className="eyebrow">WELCOME BACK!</span>
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

export default AuthPage;
