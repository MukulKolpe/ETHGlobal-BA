import "@/styles/globals.css";
import type { AppProps } from "next/app";
import WagmiProvider from "@/utils/wagmiprovider";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <WagmiProvider>
      <Component {...pageProps} />
    </WagmiProvider>
  );
}
