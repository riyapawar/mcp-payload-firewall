// Local test endpoint — echoes the request body back as-is.
// Use this to test the proxy firewall without an external MCP server.
export async function POST(req: Request) {
  const body = await req.text();
  return new Response(body, {
    headers: { "Content-Type": req.headers.get("content-type") ?? "application/json" },
  });
}
