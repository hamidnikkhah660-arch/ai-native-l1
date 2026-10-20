import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const serverScript = path.join(repoRoot, "contracts", "launch-asset", "scripts", "serve-wallet-console.mjs");

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Could not allocate a loopback test port"));
        return;
      }
      const port = address.port;
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}
async function waitForServer(url, child) {
  let lastError;
  for (let i = 0; i < 40; i++) {
    if (child.exitCode !== null) throw new Error("Wallet server exited before readiness");
    try {
      const response = await fetch(url);
      if (response.status === 200) return response;
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("Wallet server did not become ready: " + (lastError?.message || "unknown error"));
}

const port = await freePort();
const child = spawn(process.execPath, [serverScript], {
  cwd: repoRoot,
  env: { ...process.env, WALLET_CONSOLE_PORT: String(port) },
  windowsHide: true,
  stdio: ["ignore", "pipe", "pipe"]
});
let stdout = "";
let stderr = "";
child.stdout.on("data", chunk => { stdout += chunk.toString(); });
child.stderr.on("data", chunk => { stderr += chunk.toString(); });
const base = "http://127.0.0.1:" + port;

try {
  const page = await waitForServer(base + "/", child);
  const html = await page.text();
  assert.match(html, /Qanvoryx Wallet Console/);
  assert.doesNotMatch(html, /__NOT_A_REAL_PLACEHOLDER__/, "unexpected build marker does not appear");
  assert.match(page.headers.get("content-security-policy") || "", /default-src 'none'/);
  assert.match(page.headers.get("content-security-policy") || "", /connect-src 'self'/);
  assert.equal(page.headers.get("access-control-allow-origin"), null, "no permissive CORS");
  assert.equal(page.headers.get("x-content-type-options"), "nosniff");
  assert.doesNotMatch(html, /__EXPECTED_RUNTIME_CODE__|__CREATION_BYTECODE__/);

  const denied = await fetch(base + "/README.md");
  assert.equal(denied.status, 404, "server exposes only wallet page");
  const methodDenied = await fetch(base + "/", { method: "POST", body: "must not be stored" });
  assert.equal(methodDenied.status, 405, "server is GET-only");
  assert.equal(methodDenied.headers.get("allow"), "GET");
  assert.match(stdout, /127\.0\.0\.1/);
  assert.doesNotMatch(stdout + stderr, /private key|seed phrase|0x[0-9a-fA-F]{64}/i);

  process.stdout.write([
    "WALLET_LOCAL_SERVER_TEST=PASS",
    "checks=loopback-bind,only-wallet-page,GET-only,no-cors,csp,no-secret-logs",
    "public_network=not_contacted"
  ].join("\n") + "\n");
} finally {
  if (child.exitCode === null) {
    child.kill();
    await Promise.race([
      new Promise(resolve => child.once("exit", resolve)),
      new Promise(resolve => setTimeout(resolve, 1200))
    ]);
  }
}
