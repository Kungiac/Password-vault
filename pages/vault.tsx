import Head from "next/head";
import { useRouter } from "next/router";
import { useCallback, useEffect, useRef, useState } from "react";
import { Auth } from "aws-amplify";
import { useCrypto } from "../context/CryptoContext";
import { decryptPassword, encryptPassword } from "../lib/crypto";

type PasswordRow = {
  id: string;
  site_name: string;
  encrypted_password: string;
  iv: string;
};

type DecryptedRow = PasswordRow & {
  plain?: string;
  reveal: boolean;
  decryptError?: string;
};

function apiBase(): string {
  const u = process.env.NEXT_PUBLIC_API_URL ?? "";
  return u.replace(/\/$/, "");
}

export default function VaultPage(): JSX.Element {
  const router = useRouter();
  const { aesKey, clearVaultSession } = useCrypto();
  const [rows, setRows] = useState<DecryptedRow[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loadingList, setLoadingList] = useState(false);
  const [siteName, setSiteName] = useState("");
  const [sitePassword, setSitePassword] = useState("");
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const saveMessageRef = useRef<HTMLParagraphElement | null>(null);

  const authHeader = useCallback(async (): Promise<string> => {
    const session = await Auth.currentSession();
    const token = session.getIdToken().getJwtToken();
    return `Bearer ${token}`;
  }, []);

  const loadPasswords = useCallback(async () => {
    if (!aesKey) return;
    setLoadError(null);
    setLoadingList(true);
    try {
      const base = apiBase();
      if (!base) {
        throw new Error(
          "API URL is not configured. Set NEXT_PUBLIC_API_URL in .env.local."
        );
      }
      const res = await fetch(`${base}/passwords`, {
        headers: {
          Authorization: await authHeader(),
          "Content-Type": "application/json",
        },
      });
      if (!res.ok) {
        throw new Error(`Could not load entries (${res.status}).`);
      }
      const data = (await res.json()) as PasswordRow[];
      const next: DecryptedRow[] = [];
      for (const r of data) {
        const entry: DecryptedRow = { ...r, reveal: false };
        try {
          entry.plain = await decryptPassword(
            r.encrypted_password,
            r.iv,
            aesKey
          );
        } catch (e) {
          entry.decryptError =
            e instanceof Error ? e.message : "Could not decrypt";
        }
        next.push(entry);
      }
      setRows(next);
    } catch (e) {
      setLoadError(
        e instanceof Error ? e.message : "Something went wrong loading the vault."
      );
    } finally {
      setLoadingList(false);
    }
  }, [aesKey, authHeader]);

  useEffect(() => {
    if (!aesKey) {
      void router.replace("/");
    }
  }, [aesKey, router]);

  useEffect(() => {
    if (aesKey) {
      void loadPasswords();
    }
  }, [aesKey, loadPasswords]);

  useEffect(() => {
    if (saveMessage && saveMessageRef.current) {
      saveMessageRef.current.focus();
    }
  }, [saveMessage]);

  const handleSave = async () => {
    if (!aesKey) return;
    setSaveMessage(null);
    setSaveError(null);
    if (!siteName.trim() || !sitePassword) {
      setSaveError("Enter both a site name and the password to save.");
      return;
    }
    const base = apiBase();
    if (!base) {
      setSaveError("API URL is not configured. Set NEXT_PUBLIC_API_URL.");
      return;
    }
    setSaving(true);
    try {
      const { ciphertext, iv } = await encryptPassword(sitePassword, aesKey);
      const res = await fetch(`${base}/passwords`, {
        method: "POST",
        headers: {
          Authorization: await authHeader(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          siteName: siteName.trim(),
          encryptedPassword: ciphertext,
          iv,
        }),
      });
      if (res.status === 202) {
        setSaveMessage(
          "The new entry usually appears in a few seconds after refresh"
        );
        setSiteName("");
        setSitePassword("");
        return;
      }
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `Save failed (${res.status})`);
      }
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const signOut = async () => {
    await Auth.signOut();
    clearVaultSession();
    await router.replace("/");
  };

  const toggleReveal = (id: string) => {
    setRows((prev) =>
      prev.map((r) => (r.id === id ? { ...r, reveal: !r.reveal } : r))
    );
  };

  if (!aesKey) {
    return (
      <div className="pv-page">
        <main className="pv-shell">
          <p className="pv-loading" role="status">
            Returning to sign in…
          </p>
        </main>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>Your Passwords</title>
        <meta name="description" content="Your encrypted password entries." />
      </Head>
      <div className="pv-page">
        <main className="pv-shell pv-shell--wide">
          <header className="pv-header">
            <div className="pv-header__titles">
              <h1 className="pv-title-vault" style={{ marginBottom: "0.35rem" }}>
                Your Passwords
              </h1>
              <p className="pv-lead-vault" style={{ marginBottom: 0 }}>
                Entries are encrypted in your browser. The server only stores
                ciphertext.
              </p>
            </div>
            <button
              type="button"
              className="pv-btn pv-btn--sign"
              onClick={() => void signOut()}
            >
              Sign out
            </button>
          </header>

          <section className="pv-card" style={{ marginBottom: "1.5rem" }}>
            <h2 className="pv-section-title">Add entry</h2>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleSave();
              }}
            >
              <div className="pv-field">
                <label className="pv-label" htmlFor="entry-site">
                  Site or label
                </label>
                <input
                  id="entry-site"
                  className="pv-input"
                  value={siteName}
                  maxLength={100}
                  placeholder="e.g. Personal email"
                  onChange={(e) => setSiteName(e.target.value)}
                />
              </div>
              <div className="pv-field">
                <label className="pv-label" htmlFor="entry-secret">
                  Password to store
                </label>
                <input
                  id="entry-secret"
                  className="pv-input"
                  type="password"
                  autoComplete="off"
                  value={sitePassword}
                  onChange={(e) => setSitePassword(e.target.value)}
                />
                <p className="pv-hint">
                  Encrypted locally before anything is sent. Clear the field after
                  saving if you share this screen.
                </p>
              </div>
              <button
                type="submit"
                className="pv-btn pv-btn--primary"
                disabled={saving}
              >
                {saving ? "Encrypting and sending…" : "Save to vault"}
              </button>
            </form>
            {saveMessage && (
              <p
                ref={saveMessageRef}
                className="pv-banner pv-banner--success"
                style={{ marginTop: "1rem", marginBottom: 0 }}
                role="status"
                tabIndex={-1}
              >
                {saveMessage}
              </p>
            )}
            {saveError && (
              <p
                className="pv-banner pv-banner--error"
                style={{ marginTop: "1rem", marginBottom: 0 }}
                role="alert"
              >
                {saveError}
              </p>
            )}
          </section>

          <section>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "baseline",
                justifyContent: "space-between",
                gap: "0.75rem",
                marginBottom: "0.9rem",
              }}
            >
              <h2 className="pv-section-title" style={{ marginBottom: 0 }}>
                Your entries
              </h2>
              <button
                type="button"
                className="pv-btn pv-btn--sign"
                disabled={loadingList}
                onClick={() => void loadPasswords()}
              >
                {loadingList ? "Refreshing…" : "Refresh list"}
              </button>
            </div>

            {loadError && (
              <div className="pv-banner pv-banner--error" role="alert">
                {loadError}
              </div>
            )}

            {loadingList && rows.length === 0 && !loadError && (
              <p className="pv-loading" role="status">
                Loading and decrypting entries…
              </p>
            )}

            {!loadError && !loadingList && rows.length === 0 && (
              <div className="pv-empty">
                No entries yet. Add one above, wait for the queue to finish,
                then refresh.
              </div>
            )}

            <ul className="pv-list">
              {rows.map((r) => (
                <li key={r.id} className="pv-entry">
                  <h3 className="pv-entry__site">{r.site_name}</h3>
                  {r.decryptError && (
                    <p
                      className="pv-banner pv-banner--error"
                      style={{ margin: "0 0 0.5rem", fontSize: "0.85rem" }}
                    >
                      {r.decryptError}
                    </p>
                  )}
                  {r.plain !== undefined && !r.decryptError && (
                    <>
                      <p className="pv-sr-only">
                        {r.reveal ? "Password visible below." : "Password hidden."}
                      </p>
                      <p
                        id={`secret-${r.id}`}
                        className="pv-entry__secret"
                        aria-label={r.reveal ? "Password" : "Password hidden"}
                      >
                        {r.reveal ? r.plain : "••••••••••••"}
                      </p>
                      <div className="pv-entry__row">
                        <button
                          type="button"
                          className="pv-btn pv-btn--grey"
                          onClick={() => toggleReveal(r.id)}
                          aria-expanded={r.reveal}
                          aria-controls={`secret-${r.id}`}
                        >
                          {r.reveal ? "Hide password" : "Show password"}
                        </button>
                      </div>
                    </>
                  )}
                </li>
              ))}
            </ul>
          </section>
        </main>
      </div>
    </>
  );
}
