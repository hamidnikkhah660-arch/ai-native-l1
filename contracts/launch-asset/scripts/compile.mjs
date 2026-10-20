import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import solc from "solc";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const projectRoot = path.resolve(here, "..");
const sourcePath = path.join(projectRoot, "contracts", "FixedSupplyLaunchAsset.sol");

export function compileAsset() {
  const source = fs.readFileSync(sourcePath, "utf8");
  const input = {
    language: "Solidity",
    sources: { "FixedSupplyLaunchAsset.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      metadata: { bytecodeHash: "none" },
      outputSelection: {
        "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] }
      }
    }
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input), {
    import(importPath) {
      const prefix = "@openzeppelin/contracts/";
      if (!importPath.startsWith(prefix)) return { error: "Import not allowed: " + importPath };
      const resolved = path.resolve(projectRoot, "node_modules", importPath);
      const dependencyRoot = path.resolve(projectRoot, "node_modules", "@openzeppelin", "contracts") + path.sep;
      if (!resolved.startsWith(dependencyRoot)) return { error: "Import escaped OpenZeppelin package" };
      try { return { contents: fs.readFileSync(resolved, "utf8") }; }
      catch { return { error: "Unable to resolve dependency: " + importPath }; }
    }
  }));
  const errors = (output.errors ?? []).filter(item => item.severity === "error");
  if (errors.length) {
    for (const error of errors) process.stderr.write(error.formattedMessage + "\n");
    throw new Error("Solidity compilation failed");
  }
  const artifact = output.contracts?.["FixedSupplyLaunchAsset.sol"]?.FixedSupplyLaunchAsset;
  if (!artifact?.evm?.bytecode?.object) throw new Error("Compiler did not produce contract bytecode");
  return { abi: artifact.abi, bytecode: "0x" + artifact.evm.bytecode.object, deployedBytecode: "0x" + artifact.evm.deployedBytecode.object, compilerVersion: solc.version() };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const asset = compileAsset();
  process.stdout.write(JSON.stringify({
    status: "COMPILE_PASS",
    compilerVersion: asset.compilerVersion,
    bytecodeBytes: (asset.bytecode.length - 2) / 2,
    deployedBytecodeBytes: (asset.deployedBytecode.length - 2) / 2,
    abiEntries: asset.abi.length,
    evmVersion: "shanghai",
    dependency: "@openzeppelin/contracts@5.6.1"
  }, null, 2) + "\n");
}
