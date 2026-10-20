import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { projectRoot } from "./compile.mjs";

const repoRoot = path.resolve(projectRoot, "..", "..");
const pagePath = path.join(repoRoot, "tools", "evm_testnet_wallet.html");
const host = "127.0.0.1";
const port = Number(process.env.WALLET_CONSOLE_PORT || "8765");

if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error("WALLET_CONSOLE_PORT must be an integer from 1024 to 65535.");
}
if (!fs.existsSync(pagePath)) {
  throw new Error("Built wallet page is missing. Run npm run build:wallet first.");
}
const page = fs.readFileSync(pagePath);
if (page.includes("__EXPECTED_RUNTIME_CODE__") || page.includes("__CREATION_BYTECODE__")) {
  throw new Error("Wallet page contains an unresolved build marker.");
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET") {
    res.writeHead(405, { "Allow": "GET", "Cache-Control": "no-store" });
    res.end("Method not allowed\n");
    return;
  }

  let pathname;
  try { pathname = new URL(req.url || "/", "http://127.0.0.1").pathname; }
  catch {
    res.writeHead(400, { "Cache-Control": "no-store" });
    res.end("Bad request\n");
    return;
  }
  if (pathname !== "/" && pathname !== "/evm_testnet_wallet.html") {
    res.writeHead(404, { "Cache-Control": "no-store" });
    res.end("Not found\n");
    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  });
  res.end(page);
});

server.on("error", error => {
  process.stderr.write("Wallet console server failed: " + error.message + "\n");
  process.exitCode = 1;
});
server.listen(port, host, () => {
  process.stdout.write("WALLET_CONSOLE_LOCAL_ONLY=http://" + host + ":" + port + "/\n");
  process.stdout.write("Binding=" + host + " (loopback only); GET page only; no CORS; no transaction API.\n");
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
