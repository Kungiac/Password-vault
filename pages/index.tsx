import Head from "next/head";
import { useRouter } from "next/router";
import { useCallback, useEffect, useState } from "react";
import { Auth } from "aws-amplify";
import {
  isAmplifyAuthReady,
  missingAmplifyAuthEnvKeys,
} from "../lib/amplify";
import { useCrypto } from "../context/CryptoContext";
import {
  deriveKey,
  generateSalt,
  saltFromHex,
  saltToHex,
} from "../lib/crypto";

type Mode = "signIn" | "signUp" | "confirm" | "unlock";

type Feedback = {
  kind: "error" | "info" | "success";
  text: string;
};

type PasswordRule = {
  label: string;
  test: (value: string) => boolean;
};

const PASSWORD_RULES: PasswordRule[] = [
  { label: "At least 12 characters", test: (value) => value.length >= 12 },
  { label: "One lowercase letter", test: (value) => /[a-z]/.test(value) },
  { label: "One uppercase letter", test: (value) => /[A-Z]/.test(value) },
  { label: "One number", test: (value) => /\d/.test(value) },
  {
    label: "One special character",
    test: (value) => /[^A-Za-z0-9]/.test(value),
  },
];

function getPasswordStrength(passwordValue: string): {
  score: number;
  label: string;
  className: string;
} {
  if (!passwordValue) {
    return { score: 0, label: "No password entered", className: "empty" };
  }

  const passedRules = PASSWORD_RULES.filter((rule) =>
    rule.test(passwordValue)
  ).length;
  const bonusForLength =
    passwordValue.length >= 16 ? 1 : passwordValue.length >= 20 ? 2 : 0;
  const score = Math.min(5, passedRules + bonusForLength);

  if (score <= 2) {
    return { score, label: "Weak", className: "weak" };
  }
  if (score === 3) {
    return { score, label: "Fair", className: "fair" };
  }
  if (score === 4) {
    return { score, label: "Good", className: "good" };
  }
  return { score, label: "Strong", className: "strong" };
}

function saltStorageKey(sub: string): string {
  return `passwordVaultSaltHex_${sub}`;
}

export default function HomePage(): JSX.Element {
  const router = useRouter();
  const { setAesKey } = useCrypto();

  const [mode, setMode] = useState<Mode>("signIn");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmCode, setConfirmCode] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [masterPasswordConfirm, setMasterPasswordConfirm] = useState("");
  const [pendingSub, setPendingSub] = useState<string | null>(null);
  const [hasVaultSalt, setHasVaultSalt] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (pendingSub) {
      setHasVaultSalt(!!localStorage.getItem(saltStorageKey(pendingSub)));
    } else {
      setHasVaultSalt(false);
    }
  }, [pendingSub]);

  const unlockOrCreateVault = useCallback(async () => {
    setFeedback(null);
    setLoading(true);
    if (!pendingSub) {
      setFeedback({ kind: "error", text: "Missing user session." });
      setLoading(false);
      return;
    }
    const saltHex = localStorage.getItem(saltStorageKey(pendingSub));
    if (!saltHex) {
      if (masterPassword.length < 8) {
        setFeedback({
          kind: "error",
          text: "Salt must be more than 8 characters.",
        });
        setLoading(false);
        return;
      }
      if (masterPassword !== masterPasswordConfirm) {
        setFeedback({
          kind: "error",
          text: "Salt does not match",
        });
        setLoading(false);
        return;
      }
      try {
        const salt = generateSalt();
        localStorage.setItem(saltStorageKey(pendingSub), saltToHex(salt));
        setHasVaultSalt(true);
        const key = await deriveKey(masterPassword, salt);
        setAesKey(key);
        setMasterPassword("");
        setMasterPasswordConfirm("");
        await router.push("/vault");
      } catch (e) {
        setFeedback({
          kind: "error",
          text: e instanceof Error ? e.message : "Couldn't create vault",
        });
      } finally {
        setLoading(false);
      }
      return;
    }
    if (masterPassword.length < 1) {
      setFeedback({ kind: "error", text: "Enter your personal salt" });
      setLoading(false);
      return;
    }
    try {
      const key = await deriveKey(masterPassword, saltFromHex(saltHex));
      setAesKey(key);
      setMasterPassword("");
      await router.push("/vault");
    } catch (e) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Couldn't unlock vault",
      });
    } finally {
      setLoading(false);
    }
  }, [masterPassword, masterPasswordConfirm, pendingSub, router, setAesKey]);

  const afterCognitoAuth = useCallback(async () => {
    const user = await Auth.currentUserInfo();
    const sub = user.attributes?.sub ?? user.username;
    if (typeof sub !== "string" || !sub) {
      setFeedback({
        kind: "error",
        text: "Could not read Cognito user id",
      });
      return;
    }
    setPendingSub(sub);
    setMode("unlock");
    const hasSalt = !!localStorage.getItem(saltStorageKey(sub));
    setHasVaultSalt(hasSalt);
    if (!hasSalt) {
      setFeedback({
        kind: "info",
        text: "Create a salt for yourself",
      });
    } else {
      setFeedback(null);
    }
  }, []);

  const handleSignIn = async () => {
    setFeedback(null);
    setLoading(true);
    try {
      await Auth.signIn(email, password);
      await afterCognitoAuth();
    } catch (e: unknown) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Sign in failed",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSignUp = async () => {
    setFeedback(null);
    setLoading(true);
    try {
      await Auth.signUp({
        username: email,
        password,
        attributes: { email },
      });
      setMode("confirm");
      setFeedback({
        kind: "info",
        text: "Confirmation code sent to your email, enter it below",
      });
    } catch (e: unknown) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Sign up failed",
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
      setFeedback({
        kind: "success",
        text: "Your account is confirmed",
      });
    } catch (e: unknown) {
      setFeedback({
        kind: "error",
        text: e instanceof Error ? e.message : "Confirmation failed",
      });
    } finally {
      setLoading(false);
    }
  };

  const goSignIn = () => {
    setMode("signIn");
    setFeedback(null);
  };

  const goSignUp = () => {
    setMode("signUp");
    setFeedback(null);
  };

  const bannerClass =
    feedback?.kind === "error"
      ? "pv-banner pv-banner--error"
      : feedback?.kind === "success"
        ? "pv-banner pv-banner--success"
        : "pv-banner pv-banner--info";

  const passwordChecks = PASSWORD_RULES.map((rule) => ({
    label: rule.label,
    passed: rule.test(password),
  }));
  const passwordStrength = getPasswordStrength(password);

  return (
    <>
      <Head>
        <title>Password Vault — Sign in</title>
        <meta
          name="description"
          content="Sign in"
        />
      </Head>
      <div className="pv-page">
        <main className="pv-shell">
          <h1 className="pv-title">Gimme Passwords</h1>
          <p className="pv-lead">
            Create a personal salt to keep me away from your passwords
          </p>

          <div className="pv-card">
            {!isAmplifyAuthReady && (
              <div className="pv-banner pv-banner--error" role="alert">
                <strong style={{ display: "block", marginBottom: "0.35rem" }}>
                  Cognito is not configured
                </strong>
                <span>
                  Add these variables to{" "}
                  <code style={{ fontSize: "0.85em" }}>frontend/.env.local</code>{" "}
                  using values from{" "}
                  <code style={{ fontSize: "0.85em" }}>cdk deploy</code> outputs,
                  then stop and restart{" "}
                  <code style={{ fontSize: "0.85em" }}>npm run dev</code>
                  (Next.js reads{" "}
                  <code style={{ fontSize: "0.85em" }}>NEXT_PUBLIC_*</code> only at
                  startup).
                </span>
                <ul
                  style={{
                    margin: "0.65rem 0 0",
                    paddingLeft: "1.2rem",
                    fontSize: "0.88rem",
                  }}
                >
                  {missingAmplifyAuthEnvKeys().map((key) => (
                    <li key={key}>
                      <code>{key}</code>
                    </li>
                  ))}
                </ul>
                <p className="pv-hint" style={{ marginTop: "0.75rem", marginBottom: 0 }}>
                  Also set <code>NEXT_PUBLIC_API_URL</code> after deploy so the vault
                  can load and save entries.
                </p>
              </div>
            )}

            {mode !== "unlock" && mode !== "confirm" && (
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

            {feedback && (
              <div
                className={bannerClass}
                role={feedback.kind === "error" ? "alert" : "status"}
                aria-live="polite"
              >
                {feedback.text}
              </div>
            )}

            {mode === "signIn" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleSignIn();
                }}
              >
                <fieldset
                  disabled={!isAmplifyAuthReady}
                  className="pv-fieldset-reset"
                >
                <div className="pv-field">
                  <label className="pv-label" htmlFor="signin-email">
                    Email
                  </label>
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
                  <label className="pv-label" htmlFor="signin-password">
                    Password
                  </label>
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
                <button
                  type="submit"
                  className="pv-btn pv-btn--primary"
                  disabled={loading}
                >
                  {loading ? "Signing in…" : "Sign in"}
                </button>
                </fieldset>
              </form>
            )}

            {mode === "signUp" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleSignUp();
                }}
              >
                <fieldset
                  disabled={!isAmplifyAuthReady}
                  className="pv-fieldset-reset"
                >
                <div className="pv-field">
                  <label className="pv-label" htmlFor="signup-email">
                    Email
                  </label>
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
                  <label className="pv-label" htmlFor="signup-password">
                    Password
                  </label>
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
                      <span
                        className={`pv-strength-badge pv-strength-badge--${passwordStrength.className}`}
                      >
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
                      {passwordChecks.map((rule) => (
                        <li
                          key={rule.label}
                          className={
                            rule.passed
                              ? "pv-password-rules__item pv-password-rules__item--pass"
                              : "pv-password-rules__item"
                          }
                        >
                          <span aria-hidden="true">{rule.passed ? "✓" : "○"}</span>
                          {rule.label}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
                <button
                  type="submit"
                  className="pv-btn pv-btn--primary"
                  disabled={loading}
                >
                  {loading ? "Creating account…" : "Create account"}
                </button>
                </fieldset>
              </form>
            )}

            {mode === "confirm" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleConfirm();
                }}
              >
                <fieldset
                  disabled={!isAmplifyAuthReady}
                  className="pv-fieldset-reset"
                >
                <div className="pv-field">
                  <label className="pv-label" htmlFor="confirm-email">
                    Email
                  </label>
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
                  <label className="pv-label" htmlFor="confirm-code">
                    Confirmation code
                  </label>
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
                <button
                  type="submit"
                  className="pv-btn pv-btn--primary"
                  disabled={loading}
                >
                  {loading ? "Verifying…" : "Verify email"}
                </button>
                <p className="pv-hint" style={{ marginTop: "1rem" }}>
                  Already verified?{" "}
                  <button
                    type="button"
                    className="pv-btn pv-btn--ghost"
                    onClick={goSignIn}
                  >
                    Back to sign in
                  </button>
                </p>
                </fieldset>
              </form>
            )}

            {mode === "unlock" && pendingSub && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void unlockOrCreateVault();
                }}
              >
                <fieldset
                  disabled={!isAmplifyAuthReady}
                  className="pv-fieldset-reset"
                >
                <h2 className="pv-section-title">Master password</h2>
                {!hasVaultSalt && (
                  <p className="pv-hint" style={{ marginBottom: "1rem" }}>
                    If you lose this password you're cooked
                  </p>
                )}
                <div className="pv-field">
                  <label className="pv-label" htmlFor="master-password">
                    {hasVaultSalt ? "Master password" : "Choose master password"}
                  </label>
                  <input
                    id="master-password"
                    className="pv-input"
                    type="password"
                    autoComplete="off"
                    value={masterPassword}
                    onChange={(e) => setMasterPassword(e.target.value)}
                    autoFocus
                  />
                </div>
                {!hasVaultSalt && (
                  <div className="pv-field">
                    <label className="pv-label" htmlFor="master-password-2">
                      Confirm salt 
                    </label>
                    <input
                      id="master-password-2"
                      className="pv-input"
                      type="password"
                      autoComplete="off"
                      value={masterPasswordConfirm}
                      onChange={(e) => setMasterPasswordConfirm(e.target.value)}
                    />
                  </div>
                )}
                <button
                  type="submit"
                  className="pv-btn pv-btn--primary"
                  disabled={loading}
                >
                  {loading
                    ? "Working"
                    : hasVaultSalt
                      ? "Unlock vault"
                      : "Create vault and continue"}
                </button>
                </fieldset>
              </form>
            )}
          </div>
        </main>
      </div>
    </>
  );
}
