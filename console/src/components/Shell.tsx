"use client";
import { setLanguage, tr } from "@/lib/i18n";
import { LogoMark } from "@/components/Logo";
import { ChevronsUpDown, LogOut, Moon, Search, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarRail, SidebarTrigger } from "@/components/ui/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { control, useLoad } from "@/lib/api";
import { findNav, INNER, NAV } from "@/lib/nav";
import { PeopleProvider } from "@/lib/people";

// Must match the control plane's role checks; the server is what enforces them.
const CONFIG = ["admin", "compliance", "dpo", "engineer"];
const AUDIT = ["admin", "compliance", "dpo"];
const ACCESS: Record<string, string[]> = { "/residency-map": [...CONFIG, "map_editor", "exception_approver"], "/monitoring": CONFIG, "/page-protection": CONFIG, "/detection": [...CONFIG, "detection_manager", "detection_approver"], "/overview": CONFIG, "/connect": CONFIG, "/policies": CONFIG, "/pipelines": CONFIG, "/people": CONFIG, "/audit": AUDIT, "/reports": AUDIT, "/keys": ["admin", "compliance", "dpo"], "/settings": CONFIG, "/files": ["dpo", "compliance"] };

export interface Me { id: string; display_name: string; roles: string[]; tenant: { id: string; name: string; deployment: string; demo_mode?: boolean; setup_needed?: boolean } }
const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext);

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  return (
    <Button variant="ghost" size="icon" aria-label={tr("Switch theme")} title={tr("Switch theme")} onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}>
      <Sun className="hidden dark:block" /><Moon className="dark:hidden" />
    </Button>
  );
}

/** Jump to any page you are allowed to see, by name or by what you want to do. */
function PageSearch({ allowed }: { allowed: (href: string) => boolean }) {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); setOpen((o) => !o); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <>
      <Button variant="outline" size="sm" className="hidden w-64 justify-start gap-2 font-normal text-muted-foreground md:inline-flex" onClick={() => setOpen(true)}>
        <Search /><span className="flex-1 text-left">{tr("Go to a page…")}</span><kbd className="rounded border bg-muted px-1.5 font-mono text-[10px]">⌘K</kbd>
      </Button>
      <Button variant="ghost" size="icon" className="md:hidden" aria-label={tr("Go to a page")} onClick={() => setOpen(true)}><Search /></Button>
      <CommandDialog open={open} onOpenChange={setOpen} title={tr("Go to a page")} description={tr("Search pages by name or by what you want to do")}>
        <CommandInput placeholder={tr("What are you looking for?")} />
        <CommandList>
          <CommandEmpty>{tr("No page matches that.")}</CommandEmpty>
          {NAV.map((g) => {
            const items = g.items.filter((i) => allowed(i.href));
            return items.length ? (
              <CommandGroup key={g.group} heading={tr(g.group)}>
                {items.map((i) => (
                  <CommandItem key={i.href} value={`${tr(i.label)} ${tr(i.hint)}`} onSelect={() => { setOpen(false); router.push(i.href); }}>
                    <i.icon /><span className="font-medium">{tr(i.label)}</span><span className="ml-2 truncate text-xs text-muted-foreground">{tr(i.hint)}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null;
          })}
          <CommandGroup heading="Inside other pages">
            {INNER.filter((i) => allowed(i.href)).map((i) => (
              <CommandItem key={i.href} value={`${tr(i.label)} ${tr(i.hint)}`} onSelect={() => { setOpen(false); router.push(i.href); }}>
                <i.icon /><span className="font-medium">{tr(i.label)}</span><span className="ml-2 truncate text-xs text-muted-foreground">{tr(i.hint)}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}

const initials = (name?: string) => (name ?? "").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]!.toUpperCase()).join("") || "·";

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const me = useLoad<Me>(() => control("/v1/me"));
  const router = useRouter();
  // A new organisation starts with first-time setup. Only an admin can finish it.
  useEffect(() => {
    if (me.value?.tenant.setup_needed && me.value.roles.includes("admin")) router.replace("/welcome");
    // The organisation's language, chosen at setup or in Settings.
    const lang = (me.value?.tenant as { console_language?: string } | undefined)?.console_language;
    if (lang === "en" || lang === "fr") setLanguage(lang);
  }, [me.value, router]);
  const allowed = (href: string) => !ACCESS[href] || (me.value?.roles ?? []).some((r) => ACCESS[href]!.includes(r));
  const current = findNav(path);
  const active = (href: string) => path.startsWith(href) || current?.under === href;
  return (
    <MeContext.Provider value={me.value}>
      <PeopleProvider roles={me.value?.roles}>
      <TooltipProvider>
        <SidebarProvider>
          <Sidebar collapsible="icon" aria-label={tr("Main")}>
            <SidebarHeader>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton size="lg" asChild>
                    <Link href="/overview" aria-label={tr("Onshore home")}>
                      <span className="flex aspect-square size-9 items-center justify-center"><LogoMark light size={28} className="!size-7" /></span>
                      <span className="grid flex-1 text-left leading-tight"><span className="truncate text-[17px] font-medium tracking-[-0.04em] text-white">onshore</span><span className="truncate text-xs text-sidebar-foreground/70">{me.value?.tenant.name ?? "\u00a0"}</span></span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarHeader>
            <SidebarContent>
              {NAV.map((g) => {
                const items = g.items.filter((i) => allowed(i.href));
                if (!items.length) return null;
                return (
                  <SidebarGroup key={g.group} className="py-0.5">
                    <SidebarGroupLabel className="text-[11px] font-semibold tracking-wider text-sidebar-foreground/60 uppercase">{tr(g.group)}</SidebarGroupLabel>
                    <SidebarGroupContent>
                      <SidebarMenu>
                        {items.map((i) => (
                          <SidebarMenuItem key={i.href}>
                            <SidebarMenuButton asChild isActive={active(i.href)} tooltip={tr(i.label)} className="h-8 font-medium data-[active=true]:bg-sidebar-primary data-[active=true]:text-sidebar-primary-foreground data-[active=true]:shadow-md data-[active=true]:shadow-black/20">
                              <Link href={i.href} aria-current={active(i.href) ? "page" : undefined}><i.icon /><span>{tr(i.label)}</span></Link>
                            </SidebarMenuButton>
                          </SidebarMenuItem>
                        ))}
                      </SidebarMenu>
                    </SidebarGroupContent>
                  </SidebarGroup>
                );
              })}
            </SidebarContent>
            <SidebarFooter>
              <SidebarMenu>
                <SidebarMenuItem>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <SidebarMenuButton size="lg" aria-label={tr("Your account")}>
                        <Avatar className="size-8 rounded-lg"><AvatarFallback className="rounded-lg bg-sidebar-primary text-sidebar-primary-foreground text-xs font-semibold">{initials(me.value?.display_name)}</AvatarFallback></Avatar>
                        <span className="grid flex-1 text-left leading-tight"><span className="truncate font-medium text-white">{me.value?.display_name}</span><span className="truncate text-xs text-sidebar-foreground/70">{me.value?.roles.join(", ")}</span></span>
                        <ChevronsUpDown className="ml-auto size-4" />
                      </SidebarMenuButton>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent side="top" align="start" className="w-56">
                      <DropdownMenuLabel className="truncate">{me.value?.display_name}</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onSelect={async () => { await fetch("/api/session", { method: "DELETE" }); window.location.href = "/login"; }}><LogOut />{tr("Log out")}</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarFooter>
            <SidebarRail />
          </Sidebar>
          <SidebarInset className="min-w-0">
            <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-card/85 px-4 backdrop-blur">
              <SidebarTrigger className="-ml-1" aria-label={tr("Toggle navigation")} />
              <span aria-hidden className="mr-1 h-4 w-px bg-border" />
              <div className="min-w-0 flex-1 truncate text-sm">{current && current.group !== "Start" && <><span className="text-muted-foreground">{tr(current.group)}</span><span className="mx-1.5 text-muted-foreground">/</span></>}<span className="font-medium">{current ? tr(current.label) : ""}</span></div>
              {me.value?.tenant.demo_mode && <span className="badge warn hidden md:inline-flex" title={tr("This organisation exists for demos, with made-up customers. Any older history is seeded, and marked as seeded in the database. Anything you do now is live.")}>{tr("Demo organisation")}</span>}
              <PageSearch allowed={allowed} />
              <ThemeToggle />
            </header>
            <div className="mx-auto w-full max-w-[1400px] min-w-0 p-4 md:p-6">{children}</div>
          </SidebarInset>
        </SidebarProvider>
      </TooltipProvider>
      </PeopleProvider>
    </MeContext.Provider>
  );
}
