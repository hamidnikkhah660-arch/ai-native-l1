# CP-0574 â€” QFP6 read-only QAP1 Provider / Q6EA service probe

**Status:** implementation candidate; read-only service qualification only.
**Branch:** feat/cp0574-qap1-readonly-service-probe-20261109
**Base:** CP-0573 / 72c9d3885001dd4930da8d2a2241cf338d17192a.

## Scope

The QRun V06 executable now has two distinct commands:

- `--preflight`: verifies the externally pinned Genesis/Q6PN/Q6TS/Q6EA identity package and the independently administered Q6TS DynamoDB floor.
- `--probe-qap1`: performs the same preflight, then makes read-only signed Provider and Q6EA Anchor observations over their independently pinned Noise XX endpoints.

The service probe is not node startup. It does not run Provider CAS or Q6EA Anchor CAS, or advance either trusted floor record. It may create/update the local Provider floor's diagnostic OS lock file to obtain mutual exclusion. It does not publish a block, admit a transaction, acknowledge a peer, bind the node's P2P listener or mine.

## Additional config fields

The following fields are **optional for `--preflight`** and become mandatory only for `--probe-qap1`. They must be included in the same externally SHA-256-pinned JSON config when the live read-only service probe is requested:

```json
{
  "provider_noise_client_key_path": ".\\trust\\provider-client-noise.npk1",
  "q6ea_anchor_noise_client_key_path": ".\\trust\\q6ea-client-noise.npk1",
  "provider_floor_store_path": ".\\trust\\provider-floor",
  "q6ea_expected_state_path": ".\\trust\\q6ea-expected-state.q6ea",
  "q6ea_expected_state_sha256": "<64 lowercase hex characters, independently pinned SHA-256>"
}
```

The two `.npk1` files must be NPK1 envelopes produced with the existing Windows CurrentUser DPAPI Noise-key provisioner. Each envelope is bound to the exact configured network ID; the protected files must be readable under the same Windows user identity that runs the probe. The Provider and Q6EA client private keys must be different; equality causes refusal and both in-memory copies are zeroized. The JSON config never accepts plaintext private keys. Do not put a private key on a command line or in the JSON config.

The Provider floor directory must already contain the separately provisioned local Provider high-water state for the exact ECR1 Provider pin. The probe calls `ExternalCasFloorStore::open`; it does not call `initialize`, does not accept a missing floor, and does not adopt the current remote Provider response as a new trust floor. The floor record itself is read-only during the probe, but the store's OS-backed mutual-exclusion lock may create/update its diagnostic PID lock file; the output reports this local lock-metadata side effect explicitly.

The Q6EA expected-state file is a canonical Q6EA v2 state encoding. Its SHA-256 is included in the externally pinned config. The probe decodes the state and checks its network, profile, Provider Genesis digest, Q6GD descriptor commitment and consensus fingerprint against the Q6PN/Q6GD identity already accepted by preflight.

## Invocation

PowerShell:

```powershell
$configSha256 = "<64 lowercase hex characters delivered/approved through an independent channel>"
cargo run --locked --offline --bin qrun_v06_node -- --probe-qap1 --config .\\qrun-v06-node.json --config-sha256 $configSha256
```

A local `Get-FileHash` is not, by itself, an independent approval channel. The expected digest must be checked against a value delivered through a separate administrative/review channel.

## Read-only protocol path

1. Re-run the complete bootstrap preflight, including the full Genesis snapshot, Q6GD/Q6PN, dual-signed Q6TS, strongly consistent read-only Q6TS floor lookup, Q6EA receipt-key separation and Noise server-key SHA-256 pins.
2. Read and hash-check the externally pinned Q6EA expected state; decode it and require exact Q6PN/Q6GD network/profile/Genesis/consensus identity.
3. Open the existing Provider local monotonic floor using the exact Provider ID/network/genesis/receipt-key pin from Q6PN.
4. Load the two NPK1 client identities through Windows CurrentUser DPAPI; load the Provider and Q6EA server static public keys from their separately SHA-256-pinned files.
5. Construct the pinned Noise TCP Provider and Q6EA Anchor transports and the QAP1 external coordinator.
6. Call `verify_current(expected_state)`. This issues a challenge-bound signed Provider Read and a challenge-bound signed Q6EA Anchor Read, verifies their receipts and requires both authorities to agree with the exact independently pinned state and local Provider floor. The Provider TCP client now applies a 5-second connection timeout plus 10-second read/write timeouts; the Q6EA client uses its bounded connect/read/write timeouts. Both transport constructors clear their original stack copy of each client private key, their timeout/config failure paths clear the consumed copy, and the transport clears its retained copy on drop.

The probe prints PASS only if both remote signed reads and their pin/floor/state checks succeed. If a service is unreachable, a key is wrong, a state is stale, a receipt fails verification or the local Provider floor is missing/mismatched, it exits nonzero. There is no local-only or testnet fallback.

## Security and production limits

- The current `LibcruxMlDsa65VerifierCandidate` remains a candidate implementation and is not yet production-approved. Therefore a successful probe is protocol integration evidence, not a security approval or Mainnet authorization.
- Separate endpoints and separate receipt/Noise keys do not prove separate legal operators, hosts, clouds, administrators or compromise domains. Those require external operator evidence and review.
- The local Provider floor is distinct from the Q6TS profile-trust floor. Both must be independently provisioned, protected, backed up and recovered according to their own policies.
- This command does not open the QFP6 durable fork store, instantiate a frozen production consensus-parameter artifact, resume a QAP1 journal, run history sync, accept user transactions or start mining.
- Do not create production keys or activate public endpoints merely to make this probe pass. Test-only keys and local fixtures are not Mainnet credentials.

A successful result means only that the currently pinned Provider and Q6EA services returned consistent signed observations for the independently pinned Q6EA state, under the candidate cryptographic verifier. Mainnet remains gated on frozen consensus/economics, production crypto review/key custody, durable QFP6 store recovery tied to the external manifest anchor, QAP1 restart fault-injection, public P2P/history sync, independently operated nodes, security review, wallet/RPC/explorer release and genuine quote-asset/settlement liquidity.
