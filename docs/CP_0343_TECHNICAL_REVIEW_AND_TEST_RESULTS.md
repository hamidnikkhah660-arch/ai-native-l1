# CP-0343 - Repository Technical Review, PQC/EVM Status and Engineering Regression
Date: 2026-10-20
Scope: Maintainer's complete working checkout and the curated public source tree, reviewed on 20 October 2026.
The test evidence below refers to the complete maintainer checkout before the documentation refresh; it is distinct from the curated public tree and history.
Status: **Review and regression evidence recorded; no consensus/runtime source has been modified by this report.**

## Executive readout

The project contains a substantial engineering research portfolio: Rust-native ledger and networking code; state commitment and persistence candidates; monetary emission and fork/reorganisation models; authenticated peer transport and bounded-ingress work; real ML-DSA-65 verification tests and V4 hybrid-identity/transaction candidates; an independent EVM/revm lab with cross-client comparison artefacts; and a separately deployed fixed-supply EVM testnet contract plus a local browser wallet/deployment console.

This review performed a full locked/offline all-target regression of the native Rust package and the separate EVM launch-asset package. The native package passed 736 library tests and the remaining binary/integration test targets; the full test process exited 0. `cargo check --all-targets --locked --offline` and `cargo fmt --all -- --check` also exited 0. The EVM package's `npm test` exited 0 and reported pass for the fixed-supply local contract, wallet-console and loopback-server suites. Non-fatal unused-import/dead-code warnings remain.

The important architecture decision is to finish integration in a deliberate order. The working tree contains multiple high-quality candidate implementations; they must not be treated as if every candidate is already the one canonical production path. The next high-leverage work is canonical protocol integration and testnet proof, not adding more disconnected variants.

## 1. Repository and release boundary

- The review covers the maintainer's complete working checkout and the curated public-source repository.
- The complete maintainer checkout has a separate local history; public release commits remain independently versioned.
- The maintainer checkout and public curated repository are separate working trees; changes are staged against the public tree to avoid mixing private historical artefacts into it.
- The public GitHub repository is hamidnikkhah660-arch/ai-native-l1, default branch main. The documentation refresh is staged in a separate branch to preserve the current public baseline until the diff has been reviewed.
- Latest public source/docs release remains `v0.1.1-source`; the later full local CP-0338/0339/0340 tree and this CP-0343 update are not included in that public release.
- The public release is curated rather than the entire owner's working tree. Do not imply a file in the private/local tree is already accessible to public contributors.

The public copy of the white paper, roadmap and site content is updated in a separate documentation branch. This report keeps all claims tied to observed source or dated test evidence.

## 2. Native Layer-1 and monetary accounting

### Engineering assets verified by source inventory

The Rust package includes deterministic state and transaction candidates, PoW and difficulty-adjustment candidates, chain-work/fork-choice logic, snapshot and state-root structures, PFM/PFS durable-store experiments, archive range synchronization, authenticated transport, network/domain-bound transaction envelopes, bounded ingress and worker queues, key identity/rotation/revocation policies, and monetary candidate paths including MBK3/PMT3/PFM3 and hybrid V4/PMT4/PFM4 work.

The regression includes tests for canonical parsing, caps and account invariants, branch choice/reorg, snapshot tampering, persistence faults/process-kill windows, transaction replay/wrong-network rejection, ingress budget limits, recovery states, signed identity policies, ML-DSA verification, hybrid transaction parsing and archive restart/replay.

### Main remaining integration sequence

1. Freeze one canonical production network profile, Genesis, block/transaction/snapshot formats, monetary schedule, fee rules, beneficiary identity, activation and migration semantics.
2. Integrate all supply-creation and state transitions through the canonical producer, validator/importer, fork choice/reorg, persistence, archive sync, restart/replay and state roots.
3. Make founder/public-goods/miner allocations and any sponsor/contributor designation consistent with that canonical cap and public accounting.
4. Use independent conformance vectors and at least one independently implemented oracle to agree on bytes, balances, issuance counters, state roots and winning tip.
5. Reproduce results on a clean checkout and independent nodes before calling the selected path production-ready.

Gate 2 remains open. The full test run is valuable evidence for the local codebase, but test count alone does not establish frozen production consensus.

## 3. Quantum-readiness and signature review

### Real components present

- The native package pins `libcrux-ml-dsa = 0.0.4`.
- `v4_fat1_mldsa65_candidate.rs` has a real ML-DSA-65 verifier using Libcrux's portable verification function.
- The selected hash-pinned C2SP/Wycheproof fixture contains 53 cases: 48 expected valid and 5 expected invalid. The tests verify the expected acceptance/rejection results, including tampering and wrong-digest cases.
- Additional source files and checkpoints cover internal ACVP-format vectors, differential harness work and signature provenance/licence notes.
- V4 candidate transaction identity carries both Ed25519 and ML-DSA-65 public keys/signatures. Tests exercise a real verifier in opt-in candidate paths and reject invalid signature mutations.
- Identity-policy candidates include version/suite validation, key-generation handling, revocation and anti-downgrade transitions.

### What the evidence means

This is real post-quantum signature engineering and is meaningfully beyond a roadmap-only mention. It should be described as a **tested ML-DSA-65 verification and hybrid-transaction candidate**.

It does not yet justify saying that the entire native network is quantum-resistant. The V4 hybrid path and FAT1 verification are candidate/opt-in paths rather than a frozen default production transaction profile. The main Rust package's standard dependencies include classical Ed25519 and Noise transport primitives; the standard transport uses classical X25519/ChaChaPoly. The codebase still needs a single canonical signature-suite decision, migration/account-binding review, default-path integration, independent dependency/implementation audit, key lifecycle review and broader deployment qualification.

Selected Wycheproof vectors are not the full ACVP/CAVP certification, a complete third-party audit, a side-channel assessment or proof of whole-protocol post-quantum security.

## 4. Smart-contract and EVM review

### What exists

- `contracts/vm-lab` is a standalone feasibility lab pinned to `revm = 19.5.0`; it is not a dependency of the native node.
- Existing checkpoint artefacts describe tests/differentials for CALL, CREATE/runtime code, SSTORE/SLOAD, REVERT/HALT/OOG, fee settlement, nested execution, state-diff encoding/decoding and selected SELFDESTRUCT semantics against a local Ganache/EthereumJS oracle.
- The native working repository has Solidity examples and a fixed-supply ERC-20 launch-asset package. The ERC-20 test asset has an actual Ethereum Sepolia deployment, total supply 10B QX and constructor allocation 4B founder / 3B security / 3B public-goods. The contract has no privileged mint entry point and allocations are immediately transferable.
- The browser console is a local testnet-only wallet/deployment tool with guardrails for supported test networks, bytecode check, balances, transaction receipts and non-founder signer rejection.

### Current boundary

The VM lab, QXSD state-diff adapters and Type-2 execution adapters are separate from the canonical native node. The native package's current `Cargo.toml` does not include revm. The project contract workspace itself says the current node cannot deploy/execute the sample contract. There is no canonical EVM hardfork/gas profile, Ethereum transaction/signature admission, deterministic EVM code/storage state-root commitment, canonical receipts/logs/receipts-root, persistent reorg-safe EVM state, production Ethereum JSON-RPC or native-devnet deployment proof.

The EVM lab documents a separate Rust/Cargo 1.99 toolchain; the connected workstation presented Rust/Cargo 1.82.0 and had no `rustup` command available in PATH. For that reason, the EVM lab package was not rerun in this CP-0343 regression. Prior VM-lab checkpoints remain historical evidence, not a new pass in this session.

Gate 12 (native smart-contract VM integration) remains open. The next task is to freeze execution inputs, account/fee mapping, fork schedule, state/receipt commitment and storage rollback together before connecting the lab to consensus. Adding revm directly to canonical state processing without those decisions would risk consensus incompatibility.

## 5. Network, persistence, rollback and scale

### Implemented research and test surface

The source contains bounded frame/codecs, authenticated session models, pinned peer identities, ingress budget/worker queue protection, bounded archive pages/retries, deterministic chain history replay, branch/state-store models, atomic snapshot and WAL experiments, OS-backed store writer locks, rollback/CAS receipt models, and fault-injection/process-termination tests. State commitments have flat/adaptive/bucketed/incremental candidates with membership proofs and rebuild-equivalence tests.

These are good engineering foundations for deterministic resource handling, recovery and scaling work. We did not derive or certify a throughput figure in this review, so no TPS, latency, bandwidth or hardware-neutral scaling number is claimed.

### Remaining production evidence

- Canonical runtime/issuance/store/transport integration and public threat model.
- A genuinely independent, separately administered monotonic CAS/anchor provider with out-of-band trust bootstrap and no local fallback.
- Multi-host and actual storage/device/power-failure qualification; process termination on a live OS does not substitute for sudden power loss.
- Longer-lived operation across independently controlled nodes, live key rotation/revocation and peer-discovery controls.
- Independent protocol/cryptography review and reproducible release builds.

The tests include a model case where restoring the local manifest/journal and model anchor together reproduces a rollback gap. That is a useful, explicit finding for the design; Gate 8 remains open until the real independent trust boundary is integrated and qualified.

## 6. Browser wallet / EVM asset

Current local EVM tests passed:
- `LOCAL_EVM_FIXED_SUPPLY_ASSET_TEST=PASS`: exact 10B total supply, 40/30/30 allocation arithmetic, standard ERC-20 transfer/allowance flow, unchanged total supply after transfer, no privileged mint entry point, and rejection of zero/duplicate allocation addresses.
- `WALLET_CONSOLE_TEST=PASS`: non-founder signer guard, zero-balance preflight, gas estimate buffer, bytecode match, mainnet refusal, ABI reads, founder share calculation and signed testnet transfer/receipt flow.
- `WALLET_LOCAL_SERVER_TEST=PASS`: loopback-only binding, one-page GET surface, no CORS, CSP and no secret logging.

The scripts use an ephemeral local EVM; the server tests did not contact a public network. Separately, the already documented QX asset exists on Ethereum Sepolia. This is not proof of native coin Mainnet or native smart-contract execution.

## 7. Current local verification log

Executed from `src/native/pow_bench` on the connected owner's workstation:

| Command | Result |
|---|---|
| `rustc --version` | Rust 1.82.0 |
| `cargo --version` | Cargo 1.82.0 |
| `cargo fmt --all -- --check` | PASS, exit 0 |
| `cargo check --all-targets --locked --offline` | PASS, exit 0 |
| `cargo test --all-targets --locked --offline` | PASS, exit 0; 736/736 library tests; remaining targets no failures |
| `npm test` in `contracts/launch-asset` | PASS, exit 0; all three suite groups passed |
| Working tree before new CP-0343 docs | Clean |
| Non-fatal warnings | Existing unused imports/dead-code warnings |

## 8. Current launch / public status

- Native coin and production network identity/Genesis are still not frozen as a production network.
- The curated public source tree does not include all historical/internal test fixtures from the maintainer's full working checkout.
- Native Mainnet, native explorer, native EVM execution, native production wallet/RPC, real native market, liquidity, sponsor agreement and project revenue are not established by this evidence.
- Public ticker QZXB is a proposed symbol, not global trademark/market clearance.
- Legal/offer documentation and any formal engagement are deferred per the current owner priority; no filing, legal opinion, sponsor contract or regulator submission was created in this technical checkpoint. Before any activity that requires prior clearance, the launch decision needs to account for the actual product and intended audiences.

## 9. Prioritized next technical tasks

1. **Gate 2:** select one canonical profile and finish end-to-end supply/Genesis integration and independent state vectors.
2. **Gate 8:** deploy and integrate an actually independent anti-rollback trust provider, then perform multi-host failure/recovery qualification.
3. **Gate 12:** freeze EVM fork/gas/transaction/account model, receipts and EVM state-root design; then integrate the VM lab.
4. **Devnet/tooling:** multi-operator zero-value devnet with a native wallet, RPC, explorer, operator identities and incident runbooks.
5. **Cryptography:** consolidate the tested ML-DSA candidate into the selected transaction/key migration policy and independently review the resulting full protocol path.
6. **Release engineering:** public-curated source sync, checksums, reproducible build and dependency/provenance audit.
7. **Commercial delivery:** use existing assets for scoped engineering sponsorship and integration/service work while the native network moves through the above gates.

This report is a source-level engineering review and recorded test run. It is not a security certification, external audit, production-readiness sign-off or statement of live economic activity.
