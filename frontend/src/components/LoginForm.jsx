import { useState } from "react";
import { login } from "../api.js";

export default function LoginForm({ onSuccess }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
      onSuccess();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-card">
      <div className="login-card__mark" aria-hidden="true" />
      <h1 className="login-card__title">SecureAI Lab</h1>
      <p className="login-card__sub">Sign in with your account to continue.</p>

      <form onSubmit={handleSubmit} className="login-form">
        <label className="login-form__field">
          <span className="login-form__label">Email</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="username"
            disabled={busy}
          />
        </label>
        <label className="login-form__field">
          <span className="login-form__label">Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            disabled={busy}
          />
        </label>

        {error && (
          <p className="login-form__error" role="alert">
            {error}
          </p>
        )}

        <button type="submit" className="slot__browse login-form__submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
