import { auth, signOut } from "@/lib/auth";
import { NavLinks } from "@/components/NavLinks";
import { Shield } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

export default async function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();
  if (!session) redirect("/login");

  return (
    <div className="flex min-h-screen bg-zinc-950 text-zinc-100">
      <aside className="flex w-56 flex-col border-r border-zinc-800/60 bg-zinc-950 px-3 py-5">
        {/* Logo */}
        <Link
          href="/dashboard"
          className="mb-6 flex items-center gap-2.5 px-3 py-1"
        >
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-red-500/15 ring-1 ring-red-500/25">
            <Shield className="h-3.5 w-3.5 text-red-400" />
          </div>
          <span className="text-sm font-semibold tracking-tight text-zinc-200">
            MCP Firewall
          </span>
        </Link>

        <NavLinks />

        {/* User */}
        <div className="mt-auto border-t border-zinc-800/60 pt-3">
          <div className="flex items-center gap-2.5 rounded-md px-3 py-2">
            {session.user?.image && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={session.user.image}
                alt="avatar"
                className="h-6 w-6 rounded-full ring-1 ring-zinc-700"
              />
            )}
            <span className="min-w-0 flex-1 truncate text-xs text-zinc-500">
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
              className="w-full rounded-md px-3 py-1.5 text-left text-xs text-zinc-600 transition-colors hover:bg-zinc-800/50 hover:text-zinc-400"
            >
              Sign out
            </button>
          </form>
        </div>
      </aside>

      <main className="flex-1 overflow-auto p-8">{children}</main>
    </div>
  );
}
