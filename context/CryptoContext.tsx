import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

type CryptoContextValue = {
  aesKey: CryptoKey | null;
  setAesKey: (key: CryptoKey | null) => void;
  clearVaultSession: () => void;
};

const CryptoContext = createContext<CryptoContextValue | undefined>(undefined);

export function CryptoProvider({ children }: { children: ReactNode }): JSX.Element {
  const [aesKey, setAesKeyState] = useState<CryptoKey | null>(null);

  const setAesKey = useCallback((key: CryptoKey | null) => {
    setAesKeyState(key);
  }, []);

  const clearVaultSession = useCallback(() => {
    setAesKeyState(null);
  }, []);

  const value = useMemo(
    () => ({ aesKey, setAesKey, clearVaultSession }),
    [aesKey, setAesKey, clearVaultSession]
  );

  return <CryptoContext.Provider value={value}>{children}</CryptoContext.Provider>;
}

export function useCrypto(): CryptoContextValue {
  const ctx = useContext(CryptoContext);
  if (!ctx) {
    throw new Error("useCrypto must be used within CryptoProvider");
  }
  return ctx;
}
