import "./api.css";

export const metadata = {
  metadataBase: new URL("https://docs.onshorevault.com"),
  title: "API reference · Onshore docs",
  description: "Every endpoint of the Onshore data API, control API and SCIM API, with request and response schemas and a built-in client to try them.",
  icons: { icon: "/icon.svg" },
};

export default function ApiLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
