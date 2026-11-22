import "./globals.css";
export const metadata = { title: "Lagoon Pay (demo)", description: "A fictional fintech used to demonstrate Onshore. All data is synthetic." };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en-NG"><body>{children}<footer className="demo">Demo: fictional company, synthetic data</footer></body></html>;
}
