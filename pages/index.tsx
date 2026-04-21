import Head from "next/head";
import { useRouter } from "next/router";
import { useCallback, useState } from "react";
import { Auth } from "aws-amplify";
import {
  isAmplifyAuthReady,
  missingAmplifyAuthEnvKeys,
} from "../lib/amplify";
import { useCrypto } from "../context/CryptoContext";
import {
  deriveKey,
  formatVaultKey,
  generateVaultKey,
  vaultKeyToPassword,
  vaultKeyToSalt,
} from "../lib/crypto";

type Mode = "signIn" | "signUp" | "confirm" | "vaultCreated" | "unlock";

type Feedback = {
  kind: "error" | "info" | "success";
  text: string;
};

type PasswordRule = {
  label: string;
  test: (value: string) => boolean;
};

const PASSWORD_RULES: PasswordRule[] = [
  { label: "At least 12 characters", test: (v) => v.length >= 12 },
  { label: "One lowercase letter", test: (v) => /[a-z]/.test(v) },
  { label: "One uppercase letter", test: (v) => /[A-Z]/.test(v) },
  { label: "One number", test: (v) => /\d/.test(v) },
  { label: "One special character", test: (v) => /[^A-Za-z0-9]/.test(v) },
];

function getPasswordStrength(val: string): {
  score: number;
  label: string;
  className: string;
} {
  if (!val) return { score: 0, label: "No password entered", className: "empty" };
  const passed = PASSWORD_RULES.filter((r) => r.test(val)).length;
  const bonus = val.length >= 20 ? 2 : val.length >= 16 ? 1 : 0;
  const score = Math.min(5, passed + bonus);
  if (score <= 2) return { score, label: "Weak", className: "weak" };
  if (score === 3) return { score, label: "Fair", className: "fair" };
  if (score === 4) return { score, label: "Good", className: "good" };
  return { score, label: "Strong", className: "strong" };
}

function vaultKeyStorageKey(sub: string): string {
  return `passwordVaultKeyHex_${sub}`;
}

export default function HomePage(): JSX.Element {
  const router = useRouter();
  const { setAesKey } = useCrypto();

  const [mode, setMode] = useState<Mode>("signIn");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmCode, setConfirmCode] = useState("");
  const [pendingSub, setPendingSub] = useState<string | null>(null);
  const [generatedKey, setGeneratedKey] = useState("");
  const [enteredKey, setEnteredKey] = useState("");
  const [copied, setCopied] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [loading, setLoading] = useState(false);

  // Called after Cognito auth succeeds.
  // If a vault key exists in localStorage → auto-derive and go to vault.
  // Otherwise → show the unlock/recovery screen.
  const afterCognitoAuth = useCallback(async () => {
    const user = await Auth.currentUserInfo();
    const sub = user.attributes?.sub ?? user.username;
    if (typeof sub !== "string" || !sub) {
      setFeedback({ kind: "error", text: "Could not read Cognito user id." });
      return;
    }
    setPendingSub(sub);

    const existingKey = localStorage.getItem(vaultKeyStorageKey(sub));
    if (existingKey) {
      const aesKey = await deriveKey(
        vaultKeyToPassword(existingKey),
        vaultKeyToSalt(existingKey)
      );
      setAesKey(aesKey);
      await router.push("/vault");
    } else {
      setMode("unlock");
      setFeedback(null);
    }
  }, [router, setAesKey]);

  // Generate a new vault key, store it, and show it once.
  const handleCreateVault = useCallback(async () => {
    if (!pendingSub) return;
    setFeedback(null);
    setLoading(true);
    try {
      const newKey = generateVaultKey();
      localStorage.setItem(vaultKeyStorageKey(pendingSub), newKey);
      const aesKey = await deriveKey(vaultKeyToPassword(newKey), vaultKeyToSalt(newKey));
      setAesKey(aesKey);
      setGeneratedKey(newKey);
      setCopied(false);
      setMode("vaultCreated");
    } catch (e) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Could not create vault.",
      });
    } finally {
      setLoading(false);
    }
  }, [pendingSub, setAesKey]);

  // Recovery: user pastes the vault key they saved previously.
  const handleVaultKeyEntry = useCallback(async () => {
    if (!pendingSub) return;
    setFeedback(null);
    setLoading(true);
    const cleaned = enteredKey.replace(/-/g, "").toLowerCase().trim();
    if (cleaned.length !== 32) {
      setFeedback({
        kind: "error",
        text: "Vault key must be 32 hex characters (dashes are optional).",
      });
      setLoading(false);
      return;
    }
    try {
      const aesKey = await deriveKey(vaultKeyToPassword(cleaned), vaultKeyToSalt(cleaned));
      localStorage.setItem(vaultKeyStorageKey(pendingSub), cleaned);
      setAesKey(aesKey);
      await router.push("/vault");
    } catch (e) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Could not unlock vault.",
      });
    } finally {
      setLoading(false);
    }
  }, [enteredKey, pendingSub, router, setAesKey]);

  const handleSignIn = async () => {
    setFeedback(null);
    setLoading(true);
    try {
      await Auth.signIn(email, password);
      await afterCognitoAuth();
    } catch (e: unknown) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Sign in failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSignUp = async () => {
    setFeedback(null);
    setLoading(true);
    try {
      await Auth.signUp({ username: email, password, attributes: { email } });
      setMode("confirm");
      setFeedback({ kind: "info", text: "Confirmation code sent to your email." });
    } catch (e: unknown) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Sign up failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async () => {
    setFeedback(null);
    setLoading(true);
    try {
      await Auth.confirmSignUp(email, confirmCode);
      setMode("signIn");
      setFeedback({ kind: "success", text: "Account confirmed — sign in below." });
    } catch (e: unknown) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Confirmation failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const goSignIn = () => { setMode("signIn"); setFeedback(null); };
  const goSignUp = () => { setMode("signUp"); setFeedback(null); };

  const bannerClass =
    feedback?.kind === "error"
      ? "pv-banner pv-banner--error"
      : feedback?.kind === "success"
        ? "pv-banner pv-banner--success"
        : "pv-banner pv-banner--info";

  const passwordChecks = PASSWORD_RULES.map((r) => ({ label: r.label, passed: r.test(password) }));
  const passwordStrength = getPasswordStrength(password);

  return (
    <>
      <Head>
        <title>Password Vault — Sign in</title>
        <meta name="description" content="Sign in to your password vault." />
      </Head>
      <div className="pv-page">
        <main className="pv-shell">
          <h1 className="pv-title">Gimme Passwords</h1>
          <p className="pv-lead">Your passwords, encrypted in your browser.</p>

          <div className="pv-card">
            {/* Cognito not configured warning */}
            {!isAmplifyAuthReady && (
              <div className="pv-banner pv-banner--error" role="alert">
                <strong style={{ display: "block", marginBottom: "0.35rem" }}>
                  Cognito is not configured
                </strong>
                <span>
                  Add these variables to{" "}
                  <code style={{ fontSize: "0.85em" }}>frontend/.env.local</code>{" "}
                  (from <code style={{ fontSize: "0.85em" }}>cdk deploy</code> outputs),
                  then restart <code style={{ fontSize: "0.85em" }}>npm run dev</code>.
                </span>
                <ul style={{ margin: "0.65rem 0 0", paddingLeft: "1.2rem", fontSize: "0.88rem" }}>
                  {missingAmplifyAuthEnvKeys().map((key) => (
                    <li key={key}><code>{key}</code></li>
                  ))}
                </ul>
              </div>
            )}

            {/* Sign in / Sign up tab switcher */}
            {mode !== "unlock" && mode !== "confirm" && mode !== "vaultCreated" && (
              <div className="pv-segmented" role="tablist" aria-label="Account access">
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === "signIn"}
                  disabled={!isAmplifyAuthReady || mode === "signIn"}
                  onClick={goSignIn}
                >
                  Sign in
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === "signUp"}
                  disabled={!isAmplifyAuthReady || mode === "signUp"}
                  onClick={goSignUp}
                >
                  Create account
                </button>
              </div>
            )}

            {/* Feedback banner */}
            {feedback && (
              <div
                className={bannerClass}
                role={feedback.kind === "error" ? "alert" : "status"}
                aria-live="polite"
              >
                {feedback.text}
              </div>
            )}

            {/* ── Sign in ─────────────────────────────────────────────────── */}
            {mode === "signIn" && (
              <form onSubmit={(e) => { e.preventDefault(); void handleSignIn(); }}>
                <fieldset disabled={!isAmplifyAuthReady} className="pv-fieldset-reset">
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="signin-email">Email</label>
                    <input
                      id="signin-email"
                      className="pv-input"
                      type="email"
                      autoComplete="username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="signin-password">Password</label>
                    <input
                      id="signin-password"
                      className="pv-input"
                      type="password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" className="pv-btn pv-btn--primary" disabled={loading}>
                    {loading ? "Signing in…" : "Sign in"}
                  </button>
                </fieldset>
              </form>
            )}

            {/* ── Sign up ─────────────────────────────────────────────────── */}
            {mode === "signUp" && (
              <form onSubmit={(e) => { e.preventDefault(); void handleSignUp(); }}>
                <fieldset disabled={!isAmplifyAuthReady} className="pv-fieldset-reset">
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="signup-email">Email</label>
                    <input
                      id="signup-email"
                      className="pv-input"
                      type="email"
                      autoComplete="username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="signup-password">Password</label>
                    <input
                      id="signup-password"
                      className="pv-input"
                      type="password"
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                    <div className="pv-password-strength">
                      <div className="pv-password-strength__row">
                        <span className="pv-label-inline">Password strength</span>
                        <span className={`pv-strength-badge pv-strength-badge--${passwordStrength.className}`}>
                          {passwordStrength.label}
                        </span>
                      </div>
                      <div
                        className="pv-strength-meter"
                        role="progressbar"
                        aria-valuemin={0}
                        aria-valuemax={5}
                        aria-valuenow={passwordStrength.score}
                        aria-label="Password strength"
                      >
                        <div
                          className={`pv-strength-meter__fill pv-strength-meter__fill--${passwordStrength.className}`}
                          style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                        />
                      </div>
                      <ul className="pv-password-rules">
                        {passwordChecks.map((r) => (
                          <li
                            key={r.label}
                            className={r.passed ? "pv-password-rules__item pv-password-rules__item--pass" : "pv-password-rules__item"}
                          >
                            <span aria-hidden="true">{r.passed ? "✓" : "○"}</span>
                            {r.label}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <button type="submit" className="pv-btn pv-btn--primary" disabled={loading}>
                    {loading ? "Creating account…" : "Create account"}
                  </button>
                </fieldset>
              </form>
            )}

            {/* ── Confirm email ────────────────────────────────────────────── */}
            {mode === "confirm" && (
              <form onSubmit={(e) => { e.preventDefault(); void handleConfirm(); }}>
                <fieldset disabled={!isAmplifyAuthReady} className="pv-fieldset-reset">
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="confirm-email">Email</label>
                    <input
                      id="confirm-email"
                      className="pv-input"
                      type="email"
                      autoComplete="username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="confirm-code">Confirmation code</label>
                    <input
                      id="confirm-code"
                      className="pv-input"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      value={confirmCode}
                      onChange={(e) => setConfirmCode(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" className="pv-btn pv-btn--primary" disabled={loading}>
                    {loading ? "Verifying…" : "Verify email"}
                  </button>
                  <p className="pv-hint" style={{ marginTop: "1rem" }}>
                    Already verified?{" "}
                    <button type="button" className="pv-btn pv-btn--ghost" onClick={goSignIn}>
                      Back to sign in
                    </button>
                  </p>
                </fieldset>
              </form>
            )}

            {/* ── Vault key — shown once on first creation ─────────────────── */}
            {mode === "vaultCreated" && (
              <div>
                <h2 className="pv-section-title">Your vault key</h2>
                <p className="pv-hint" style={{ marginBottom: "1rem" }}>
                  Save this somewhere safe — a password manager, printed paper, anywhere secure.
                  If you clear your browser data you will need it to unlock your vault.{" "}
                  <strong>It will not be shown again.</strong>
                </p>
                <div
                  style={{
                    fontFamily: "monospace",
                    fontSize: "1.05rem",
                    letterSpacing: "0.08em",
                    background: "var(--surface-alt, #f0f0f0)",
                    border: "1px solid var(--border, #ddd)",
                    borderRadius: "8px",
                    padding: "1rem",
                    textAlign: "center",
                    marginBottom: "1rem",
                    wordBreak: "break-all",
                    userSelect: "all",
                  }}
                  aria-label="Vault key"
                >
                  {formatVaultKey(generatedKey)}
                </div>
                <button
                  type="button"
                  className="pv-btn pv-btn--ghost"
                  style={{ width: "100%", marginBottom: "0.75rem" }}
                  onClick={() => {
                    void navigator.clipboard.writeText(formatVaultKey(generatedKey));
                    setCopied(true);
                  }}
                >
                  {copied ? "Copied!" : "Copy key"}
                </button>
                <button
                  type="button"
                  className="pv-btn pv-btn--primary"
                  style={{ width: "100%" }}
                  onClick={() => void router.push("/vault")}
                >
                  Open vault
                </button>
              </div>
            )}

            {/* ── Unlock / recovery — enter saved vault key ────────────────── */}
            {mode === "unlock" && pendingSub && (
              <div>
                <form onSubmit={(e) => { e.preventDefault(); void handleVaultKeyEntry(); }}>
                  <fieldset disabled={!isAmplifyAuthReady} className="pv-fieldset-reset">
                    <h2 className="pv-section-title">Enter your vault key</h2>
                    <p className="pv-hint" style={{ marginBottom: "1rem" }}>
                      Paste the vault key you saved when you first created your vault.
                    </p>
                    <div className="pv-field">
                      <label className="pv-label" htmlFor="vault-key-input">Vault key</label>
                      <input
                        id="vault-key-input"
                        className="pv-input"
                        type="text"
                        autoComplete="off"
                        spellCheck={false}
                        value={enteredKey}
                        onChange={(e) => setEnteredKey(e.target.value)}
                        placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"
                        autoFocus
                      />
                    </div>
                    <button type="submit" className="pv-btn pv-btn--primary" disabled={loading}>
                      {loading ? "Unlocking…" : "Unlock vault"}
                    </button>
                  </fieldset>
                </form>
                <p className="pv-hint" style={{ marginTop: "1.5rem", textAlign: "center" }}>
                  First time here?{" "}
                  <button
                    type="button"
                    className="pv-btn pv-btn--ghost"
                    disabled={loading}
                    onClick={() => void handleCreateVault()}
                  >
                    Create new vault
                  </button>
                </p>
              </div>
            )}
          </div>
        </main>
      </div>
    </>
  );
}
