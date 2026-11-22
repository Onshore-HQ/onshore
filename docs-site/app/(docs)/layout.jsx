import { Footer, Layout, Navbar } from "nextra-theme-docs";
import { Banner, Head } from "nextra/components";
import { getPageMap } from "nextra/page-map";
import { Logo } from "../../components/Logo";
import "nextra-theme-docs/style.css";
import "../globals.css";

export const metadata = {
  metadataBase: new URL("https://docs.onshorevault.com"),
  title: { default: "Onshore documentation", template: "%s · Onshore docs" },
  description: "How to set up, use, integrate and run Onshore: open-source data residency that keeps customer data in its country while your global tools keep working.",
  icons: { icon: "/icon.svg" },
};

export default async function RootLayout({ children }) {
  const navbar = <Navbar logo={<Logo />} />;
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head color={{ hue: 214, saturation: 72, lightness: { light: 48, dark: 62 } }} />
      <body>
        <Layout
          banner={<Banner storageKey="early-access">Onshore is in early access. Don&rsquo;t load real customer data until the items in <a href="/operate/known-limits/" style={{ textDecoration: "underline" }}>Known limits</a> are closed.</Banner>}
          navbar={navbar}
          pageMap={await getPageMap()}
          footer={<Footer>© 2026 Onshore · Nothing in these docs is legal advice.</Footer>}
          sidebar={{ defaultMenuCollapseLevel: 1, toggleButton: true }}
          toc={{ backToTop: true }}
          editLink={null}
          feedback={{ content: null }}
        >
          {children}
        </Layout>
      </body>
    </html>
  );
}
