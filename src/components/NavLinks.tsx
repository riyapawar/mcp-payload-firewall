"use client";

import { cn } from "@/lib/utils";
import {
  BarChart2,
  FileText,
  KeyRound,
  Server,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const nav = [
  { href: "/dashboard", label: "Dashboard", icon: BarChart2 },
  { href: "/rules", label: "DLP Rules", icon: ShieldAlert },
  { href: "/servers", label: "MCP Servers", icon: Server },
  { href: "/tokens", label: "API Tokens", icon: KeyRound },
  { href: "/logs", label: "Audit Logs", icon: FileText },
];

export function NavLinks() {
  const pathname = usePathname();

  return (
    <nav className="flex flex-1 flex-col gap-0.5">
      {nav.map(({ href, label, icon: Icon }) => {
        const active =
          pathname === href ||
          (href !== "/dashboard" && pathname.startsWith(href));
        return (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
              active
                ? "bg-zinc-800 text-zinc-100"
                : "text-zinc-500 hover:bg-zinc-800/50 hover:text-zinc-300"
            )}
          >
            <Icon
              className={cn(
                "h-4 w-4 shrink-0",
                active ? "text-zinc-300" : "text-zinc-600"
              )}
            />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
