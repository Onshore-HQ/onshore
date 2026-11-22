import { Activity, BarChart3, FileClock, ClipboardList, Database, FileChartColumn, FileText, KeyRound, LayoutDashboard, ListChecks, LucideIcon, MapIcon, Plug, Plus, ScanSearch, ScrollText, Settings, ShieldCheck, Upload, Users, Vault } from "lucide-react";

export interface NavItem { href: string; label: string; icon: LucideIcon; hint: string; /** Lights up this menu item instead of having its own. */ under?: string }

/** Grouped by the job a person came to do, not by how the product is built. `hint` is shown in the page search. */
export const NAV: { group: string; items: NavItem[] }[] = [
  { group: "Start", items: [{ href: "/overview", label: "Home", icon: LayoutDashboard, hint: "What to do next, and what needs attention" }] },
  { group: "See", items: [{ href: "/residency-map", label: "Residency map", icon: MapIcon, hint: "Where your data goes, and what is fixed" }] },
  { group: "Protect", items: [
    { href: "/pipelines", label: "Connections", icon: Plug, hint: "Logs, AI tools, web APIs and support tools going through Onshore" },
    { href: "/detection", label: "Data types", icon: ScanSearch, hint: "What counts as sensitive: each country's IDs, and your own" },
    { href: "/vaults", label: "Vaults", icon: Vault, hint: "Where sensitive values are kept, and how they are replaced" },
    { href: "/files", label: "Redact a file", icon: FileText, hint: "Remove sensitive data from a PDF, image or recording" },
  ] },
  { group: "Control", items: [
    { href: "/records", label: "Customer records", icon: Database, hint: "Find a person, export or erase their data" },
    { href: "/people", label: "People", icon: Users, hint: "Team members and service accounts" },
    { href: "/policies", label: "Access rules", icon: ScrollText, hint: "Who can see real values, from which networks" },
  ] },
  { group: "Prove", items: [
    { href: "/reports", label: "Reports", icon: FileChartColumn, hint: "Signed evidence for regulators and auditors" },
    { href: "/audit", label: "Audit log", icon: ClipboardList, hint: "Who did what, and when" },
  ] },
  { group: "Admin", items: [
    { href: "/keys", label: "Encryption keys", icon: KeyRound, hint: "Master key, data keys and rotation" },
    { href: "/usage", label: "Usage", icon: BarChart3, hint: "Values protected, shown and refused, and response times, over any period" },
    { href: "/logs", label: "Service logs", icon: FileClock, hint: "Every request each service handled, by request ID" },
    { href: "/monitoring", label: "Health & alerts", icon: Activity, hint: "Is every service answering, and where alerts go" },
    { href: "/settings", label: "Settings", icon: Settings, hint: "Organisation, sign-in, licence and retention" },
  ] },
];

/** Pages reached from inside another page. They are searchable, but not in the menu. */
export const INNER: (NavItem & { group: string })[] = [
  { href: "/connect", label: "Connect something", icon: Plus, hint: "Choose what to protect: logs, AI, error tools, pages, databases", group: "Protect", under: "/pipelines" },
  { href: "/page-protection", label: "Page protection", icon: ShieldCheck, hint: "Scripts running on your payment and signup pages", group: "Protect", under: "/pipelines" },
  { href: "/records/import", label: "Import existing data", icon: Upload, hint: "Load customers you already hold from a CSV, and get tokens back", group: "Control", under: "/records" },
  { href: "/onboarding", label: "Setup guide", icon: ListChecks, hint: "A guided first connection, with a sandbox vault", group: "Start", under: "/overview" },
];

export const findNav = (path: string) => [...NAV.flatMap((g) => g.items.map((i) => ({ ...i, group: g.group }))), ...INNER].sort((a, b) => b.href.length - a.href.length).find((i) => path.startsWith(i.href));
