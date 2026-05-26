/**
 * Loads the WASM binary and returns the instantiated module exports.
 * Called once per edge isolate; subsequent calls return the cached instance.
 *
 * In the Vercel Edge Runtime, WebAssembly.instantiate() accepts a Response
 * directly via streaming compilation, keeping initialisation under 1ms on warm
 * isolates (the binary is only fetched on cold start).
 */

let wasmInstance: WebAssembly.Instance | null = null;
let wasmExports: Record<string, unknown> | null = null;

export async function getWasmExports(): Promise<Record<string, unknown>> {
  if (wasmExports) return wasmExports;

  // In Edge Runtime, fetch() resolves relative URLs against the deployment origin.
  // We serve the binary from /public/wasm/ which maps to /wasm/.
  const response = await fetch(
    new URL("/wasm/firewall_engine_bg.wasm", "http://localhost")
  );

  const { instance } = await WebAssembly.instantiateStreaming(response);
  wasmInstance = instance;
  wasmExports = instance.exports as Record<string, unknown>;
  return wasmExports;
}
