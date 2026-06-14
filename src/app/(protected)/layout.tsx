import { auth, signOut } from "@/lib/auth";
import { cn } from "@/lib/utils";
import {
  BarChart2,
  FileText,
  KeyRound,
  LogOut,
  Server,
  Shield,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

const nav = [
  { href: "/dashboard", label: "Dashboard", icon: BarChart2 },
  { href: "/rules", label: "DLP Rules", icon: ShieldAlert },
  { href: "/servers", label: "MCP Servers", icon: Server },
  { href: "/tokens", label: "API Tokens", icon: KeyRound },
  { href: "/logs", label: "Audit Logs", icon: FileText },
];

export default async function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();
  if (!session) redirect("/login");

  return (
    <div className="flex min-h-screen bg-zinc-950 text-zinc-100">
      {/* Sidebar */}
      <aside className="flex w-60 flex-col border-r border-zinc-800 bg-zinc-900 px-4 py-6">
        <div className="mb-8 flex items-center gap-2.5 px-2">
          <Shield className="h-5 w-5 text-red-400" />
          <span className="font-semibold tracking-tight">MCP Firewall</span>
        </div>

        <nav className="flex flex-1 flex-col gap-1">
          {nav.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          ))}
        </nav>

        <div className="mt-auto border-t border-zinc-800 pt-4">
          <div className="mb-3 flex items-center gap-2.5 px-2">
            {session.user?.image && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={session.user.image}
                alt="avatar"
                className="h-7 w-7 rounded-full"
              />
            )}
            <span className="truncate text-xs text-zinc-400">
              {session.user?.email}
            </span>
          </div>
          <form
            action={async () => {
              "use server";
              await signOut({ redirectTo: "/login" });
            }}
          >
            <button
              type="submit"
              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
            >
              <LogOut className="h-4 w-4" />
              Sign out
            </button>
          </form>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto p-8">{children}</main>
    </div>
  );
}
