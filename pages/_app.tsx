import type { AppProps } from "next/app";
import "../styles/globals.css";
import "../lib/amplify";
import { CryptoProvider } from "../context/CryptoContext";

export default function App({ Component, pageProps }: AppProps): JSX.Element {
  return (
    <CryptoProvider>
      <Component {...pageProps} />
    </CryptoProvider>
  );
}
