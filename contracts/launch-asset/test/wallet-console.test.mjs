import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { compileAsset } from "../scripts/compile.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const htmlPath = path.join(repoRoot, "tools", "evm_testnet_wallet.html");
const html = fs.readFileSync(htmlPath, "utf8");
assert.match(html, /id="deployFounder"[^>]*value=""/, "founder treasury field ships blank rather than exposing an owner-specific wallet address");
assert.match(html, /has 0 native balance/i, "zero-balance signer is blocked before requesting wallet signature");
assert.match(html, /eth_estimateGas/, "deployment gas is preflighted before requesting wallet signature");
assert.match(html, /id="deploySecurity"[^>]*value=""/, "security reserve field ships blank");
assert.match(html, /id="deployPublicGoods"[^>]*value=""/, "public-goods field ships blank");
assert.notEqual("0x2222222222222222222222222222222222222222", "0x5555555555555555555555555555555555555555", "test allocation destinations are distinct");
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/i);
assert.ok(scriptMatch, "built wallet console contains an inline script");

const compiled = compileAsset();
const expectedRuntime = compiled.deployedBytecode.toLowerCase();
const expectedCreation = compiled.bytecode.toLowerCase();
assert.ok(html.includes('const EXPECTED_RUNTIME_CODE = "' + expectedRuntime + '";'), "console embeds exact runtime bytecode");
assert.ok(html.includes('const CREATION_BYTECODE = "' + expectedCreation + '";'), "console embeds exact creation bytecode");
assert.match(html, /Base Sepolia/);
assert.match(html, /Ethereum Sepolia/);
assert.match(html, /private key or seed phrase/i);
assert.doesNotMatch(html, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/, "console makes no direct unapproved network calls");

class FakeElement {
  constructor(id, value = "") {
    this.id=id;this.value=value;this.textContent="";this.className="";
    this.disabled=["readBtn","transferBtn","deployBtn"].includes(id);
    this.handlers={};
  }
  addEventListener(type,fn){(this.handlers[type] ||= []).push(fn);}
  async fire(type){for(const fn of this.handlers[type]||[])await fn({target:this});}
}

const ids=[
  "connectBtn","readBtn","walletStatus","deployName","deploySymbol","deployFounder",
  "deploySecurity","deployPublicGoods","deployBtn","deployStatus","tokenAddress","founderAddress",
  "networkOut","chainOut","tokenOut","tokenAddressOut","supplyOut","walletBalanceOut",
  "walletAddressOut","founderBalanceOut","founderShareOut","readStatus","recipientAddress",
  "transferAmount","transferBtn","transferStatus"
];
const elements=new Map(ids.map(id=>[id,new FakeElement(id)]));
const $=id=>elements.get(id);
let connected="0x1111111111111111111111111111111111111111";
const founder=connected;
const security="0x2222222222222222222222222222222222222222";
const publicGoods="0x5555555555555555555555555555555555555555";
const recipient="0x3333333333333333333333333333333333333333";
const tokenAddress="0x4444444444444444444444444444444444444444";
const scale=10n**18n;
let nativeBalance=100n*scale;
const supply=10_000_000_000n*scale;
const balances=new Map();
let chainId="0x14a34";
let codeOverride=null;
let deployed=false;
let pending=null;
let txCounter=0;
const listeners={};
const transactions=[];
function uintWord(n){return BigInt(n).toString(16).padStart(64,"0");}
function encodeString(s){
  const bytes=Buffer.from(s,"utf8");
  const padded=Buffer.from(bytes).toString("hex").padEnd(Math.ceil(bytes.length/32)*64,"0");
  return "0x"+uintWord(32)+uintWord(bytes.length)+padded;
}
function decodeConstructorString(args,offsetWord){
  const offset=Number(BigInt("0x"+args.slice(offsetWord*64,(offsetWord+1)*64)));
  const offsetHex=offset*2;
  const size=Number(BigInt("0x"+args.slice(offsetHex,offsetHex+64)));
  return Buffer.from(args.slice(offsetHex+64,offsetHex+64+size*2),"hex").toString("utf8");
}
function constructorAddress(args,slot){
  return "0x"+args.slice(slot*64+24,slot*64+64).toLowerCase();
}
const ethereum={
  on(event,fn){(listeners[event] ||= []).push(fn);},
  async request({method,params=[]}){
    switch(method){
      case "eth_requestAccounts": return [connected];
      case "eth_chainId": return chainId;
      case "eth_getBalance": return "0x"+uintWord(nativeBalance);
      case "eth_estimateGas": return "0x"+BigInt(3986247).toString(16);
      case "eth_gasPrice": return "0x"+BigInt(2_000_000_000).toString(16);
      case "eth_getCode":
        if(codeOverride!==null)return codeOverride;
        return deployed&&String(params[0]).toLowerCase()===tokenAddress.toLowerCase()?expectedRuntime:"0x";
      case "eth_call": {
        const call=params[0], selector=call.data.slice(0,10).toLowerCase();
        assert.equal(call.to.toLowerCase(),tokenAddress.toLowerCase());
        if(selector==="0x06fdde03")return encodeString("Qanvoryx Launch Candidate");
        if(selector==="0x95d89b41")return encodeString("QX");
        if(selector==="0x313ce567")return "0x"+uintWord(18);
        if(selector==="0x18160ddd")return "0x"+uintWord(supply);
        if(selector==="0x70a08231"){
          const addr="0x"+call.data.slice(-40).toLowerCase();
          return "0x"+uintWord(balances.get(addr)||0n);
        }
        throw new Error("Unexpected eth_call selector "+selector);
      }
      case "eth_sendTransaction": {
        const tx=params[0];
        transactions.push(tx);
        const hash="0x"+(++txCounter).toString(16).padStart(64,"0");
        if(!tx.to){
          assert.equal(tx.from.toLowerCase(),connected.toLowerCase());
          assert.ok(tx.data.toLowerCase().startsWith(expectedCreation),"deployment uses compiled creation bytecode");
          const args=tx.data.slice(expectedCreation.length);
          assert.equal(BigInt("0x"+args.slice(0,64)),160n,"name ABI offset");
          assert.equal(decodeConstructorString(args,0),"Qanvoryx Launch Candidate");
          assert.equal(decodeConstructorString(args,1),"QX");
          const deployFounder=constructorAddress(args,2);
          const deploySecurity=constructorAddress(args,3);
          const deployPublic=constructorAddress(args,4);
          assert.equal(deployFounder,founder.toLowerCase());
          assert.equal(deploySecurity,security.toLowerCase());
          assert.equal(deployPublic,publicGoods.toLowerCase());
          assert.equal(new Set([deployFounder,deploySecurity,deployPublic]).size,3);
          pending={type:"deploy",hash,founder:deployFounder,security:deploySecurity,publicGoods:deployPublic};
          return hash;
        }
        assert.equal(tx.to.toLowerCase(),tokenAddress.toLowerCase());
        assert.equal(tx.data.slice(0,10),"0xa9059cbb");
        const to="0x"+tx.data.slice(34,74).toLowerCase();
        const amount=BigInt("0x"+tx.data.slice(74,138));
        const from=tx.from.toLowerCase();
        assert.ok((balances.get(from)||0n)>=amount,"sender must have balance");
        pending={type:"transfer",from,to,amount,hash};
        return hash;
      }
      case "eth_getTransactionReceipt": {
        if(!pending||params[0]!==pending.hash)return null;
        const t=pending;
        pending=null;
        if(t.type==="deploy"){
          deployed=true;
          balances.set(t.founder,4_000_000_000n*scale);
          balances.set(t.security,3_000_000_000n*scale);
          balances.set(t.publicGoods,3_000_000_000n*scale);
          return {transactionHash:t.hash,status:"0x1",blockNumber:"0x2",contractAddress:tokenAddress};
        }
        balances.set(t.from,(balances.get(t.from)||0n)-t.amount);
        balances.set(t.to,(balances.get(t.to)||0n)+t.amount);
        return {transactionHash:t.hash,status:"0x1",blockNumber:"0x3"};
      }
      default: throw new Error("Unexpected RPC method "+method);
    }
  }
};
const window={ethereum};
vm.runInNewContext(scriptMatch[1],{
  window,document:{getElementById:$},TextDecoder,TextEncoder,Uint8Array,Buffer,
  setTimeout:(fn)=>setTimeout(fn,0),clearTimeout,console
});

async function main(){
  $("deployName").value="Qanvoryx Launch Candidate";
  $("deploySymbol").value="QX";
  $("deployFounder").value=founder;
  $("deploySecurity").value=security;
  $("deployPublicGoods").value=publicGoods;
  await $("connectBtn").fire("click");
  assert.match($("walletStatus").textContent,/Wallet connected on Base Sepolia/i);
  assert.equal($("readBtn").disabled,false);
  assert.equal($("deployBtn").disabled,false);

  // A treasury account other than the funded founder wallet must not deploy.
  connected=publicGoods;
  for(const fn of listeners.accountsChanged||[])fn([connected]);
  await $("deployBtn").fire("click");
  assert.match($("deployStatus").textContent,/does not match the founder treasury/i);
  assert.equal(transactions.length,0,"a non-founder MetaMask account must never trigger a deployment transaction");
  connected=founder;
  for(const fn of listeners.accountsChanged||[])fn([connected]);
  await $("connectBtn").fire("click");

  // A zero-balance signer must be stopped before the wallet is asked to sign.
  nativeBalance=0n;
  await $("deployBtn").fire("click");
  assert.match($("deployStatus").textContent,/has 0 native balance/i);
  assert.equal(transactions.length,0,"zero-balance account must never trigger a wallet transaction");

  // Wallet-signature deployment is simulated against the pinned compiler output after funding the exact signer.
  nativeBalance=100n*scale;
  await $("deployBtn").fire("click");
  if(transactions.length!==1)throw new Error("Deployment UI failed before sending transaction: "+$("deployStatus").textContent);
  assert.equal(transactions.length,1);
  assert.equal(transactions[0].from.toLowerCase(),connected.toLowerCase());
  assert.equal(transactions[0].to,undefined,"deployment must be a contract-creation transaction");
  assert.equal(deployed,true);
  assert.match($("deployStatus").textContent,/Testnet contract deployed/i);
  assert.equal($("tokenAddress").value,tokenAddress);
  assert.equal($("tokenOut").textContent,"Qanvoryx Launch Candidate (QX)");
  assert.equal($("supplyOut").textContent,"10,000,000,000 QX");
  assert.equal($("walletBalanceOut").textContent,"4,000,000,000 QX");
  assert.equal($("founderBalanceOut").textContent,"4,000,000,000 QX");
  assert.match($("founderShareOut").textContent,/40\.00%/);
  assert.match($("readStatus").textContent,/Exact runtime bytecode matched/i);
  assert.equal($("transferBtn").disabled,false);

  // Switching between two allowed testnets still requires re-verification on the exact chain.
  $("recipientAddress").value=recipient;
  $("transferAmount").value="1";
  chainId="0xaa36a7";
  await $("transferBtn").fire("click");
  assert.match($("transferStatus").textContent,/Network changed since token verification/i);
  assert.equal(transactions.length,1,"chain mismatch must never send a transaction");
  assert.equal($("transferBtn").disabled,true);
  await $("readBtn").fire("click");
  assert.equal($("networkOut").textContent,"Ethereum Sepolia");
  assert.equal($("transferBtn").disabled,false);

  // Non-matching bytecode must disable transfers before any token operation.
  codeOverride="0x6000";
  await $("readBtn").fire("click");
  assert.match($("readStatus").textContent,/does not match/i);
  assert.equal($("transferBtn").disabled,true);

  // Mainnet must be rejected.
  codeOverride=null;
  chainId="0x1";
  await $("readBtn").fire("click");
  assert.match($("readStatus").textContent,/Only Base Sepolia/i);
  assert.equal($("transferBtn").disabled,true);
  assert.equal($("deployBtn").disabled,true);

  chainId="0xaa36a7";
  await $("readBtn").fire("click");
  assert.equal($("networkOut").textContent,"Ethereum Sepolia");
  assert.equal($("transferBtn").disabled,false);

  $("transferAmount").value="1e2";
  await $("transferBtn").fire("click");
  assert.match($("transferStatus").textContent,/plain decimal number/i);
  assert.equal(transactions.length,1,"invalid scientific notation never reaches wallet signing");

  const before=balances.get(connected.toLowerCase());
  $("transferAmount").value="25.5";
  await $("transferBtn").fire("click");
  assert.equal(transactions.length,2);
  assert.equal(transactions[1].from.toLowerCase(),connected.toLowerCase());
  assert.equal(transactions[1].to.toLowerCase(),tokenAddress.toLowerCase());
  assert.equal(transactions[1].data.slice(0,10),"0xa9059cbb");
  assert.equal("0x"+transactions[1].data.slice(34,74).toLowerCase(),recipient.toLowerCase());
  assert.equal(BigInt("0x"+transactions[1].data.slice(74,138)),25n*scale+scale/2n);
  assert.equal(balances.get(connected.toLowerCase()),before-(25n*scale+scale/2n));
  assert.equal($("walletBalanceOut").textContent,"3,999,999,974.5 QX");
  assert.match($("transferStatus").textContent,/Confirmed on testnet/i);

  process.stdout.write([
    "WALLET_CONSOLE_TEST=PASS",
    "checks=non-founder-signer-rejection,zero-balance-signer-preflight,gas-estimate-with-25pct-buffer,owner-specified-founder-default,constructor-allocation-encoding,bytecode-match,mainnet-reject,live-ABI-read,actual-founder-share,invalid-amount-reject,extension-signed-transfer,receipt-confirmation",
    "secret_handling=none",
    "public_network=not_contacted"
  ].join("\n")+"\n");
}
main().catch(error=>{console.error(error);process.exitCode=1;});
