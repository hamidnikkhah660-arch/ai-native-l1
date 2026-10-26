# CP-0420 ? QZBE fork-choice continuation from a validated checkpoint

Date: 2026-10-26

Status: **in-memory checkpoint continuation passed locally; exact-head CI pending; no durable-store integration**

## What changed

- Added V04ExecutionForkChoiceCandidate::from_checkpoint_record. It calls the CP-0419 record validator with the explicitly supplied Genesis manifest/profile/PoW context, restores the encoded QZP4 state and bounded target/timestamp history, and seeds the branch graph with the checkpoint's QZBE consensus tip and cumulative chainwork.
- Added rebuild_from_checkpoint to replay a bounded suffix through normal envelope decoding, PoW verification, transaction/state-transition admission, and cumulative-work fork choice. Its replay input has limits on block count, envelope size, total suffix bytes and suffix depth before insertion.
- The 1,024-height guard now applies to the bounded suffix after the graph's trusted base; an ordinary graph created from Genesis still cannot grow past absolute height 1,024. A checkpoint-based graph can accept a next block at logical height 2,017 when the trusted base is height 2,016 and its 2,016-entry difficulty history was validated.
- Added public accessors for the selected chainwork and canonical target/timestamp history so future durable checkpoint commits can be built from branch state rather than guessed metadata.
- Added canonical_checkpoint_record so the running fork-choice candidate constructs the next checkpoint record directly from the selected state, QZBE consensus tip, cumulative chainwork, and branch-derived target history; only the previous checkpoint commitment remains a store/trust-layer input.

## Local evidence

The focused CP-0419/0420 checkpoint test module passed **7/7** after separating the original Genesis identity from the checkpoint segment base. The new continuation test:
1. Constructs a profile-bound state at logical height 2,016 and the exact configured 2,016-block target/timestamp suffix.
2. Creates a checkpoint fixture with an explicitly trusted synthetic QZBE tip and nonzero chainwork anchor.
3. Loads that record into a checkpoint-based fork-choice graph.
4. Mines and admits a real QZBE envelope at height 2,017 using the configured retarget window and an isolated easy-PoW test profile.
5. Replays that suffix from the same checkpoint and verifies identical canonical tip, state root and cumulative work.
6. Constructs and round-trips the next checkpoint from the post-block canonical branch, checking height, state root, total-mined counter, cumulative work and target-history height against the live fork-choice state.

The candidate uses a synthetic trusted checkpoint fixture; no claim is made that the preceding 2,016 QZBE proof-of-work blocks were actually produced. This checkpoint graph is in-memory only until CP-0421's separate durable suffix-store candidate is selected and integrated into the live node.

cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check, cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked, and the independent CP-0419 Genesis checkpoint oracle all passed locally. The parent commit 9c78832123e37b5ccb646ee7cb0756c542ead155 passed exact-head GitHub Actions run 40377595429 (Linux full suite/check and Windows integration); that result does not cover the current CP-0420 edits. New exact-head CI must pass before this checkpoint is considered validated.

## Important test limitation

The test does **not** mine and verify 2,016 earlier QZBE PoW envelopes. Its height-2,016 state/history is a profile-bound state-transition fixture, while the checkpoint's QZBE tip and cumulative-work value are explicitly treated as trusted inputs. The test proves that the software can validate the checkpoint's schema, restore its monetary state/history, and validate the next QZBE block against that base; it does not prove that the supplied checkpoint is an earned PoW chain tip. Production must establish checkpoint authenticity, ancestry and chainwork by trusted replay or an independently operated signed checkpoint/anti-rollback mechanism.

## Still missing

- The existing V04ExecutionForkStoreCandidate persists full envelope history and replays from Genesis. It does not yet persist the CP-0419 record in its manifest or use rebuild_from_checkpoint during restart.
- The persistent archive still has a 1,024 absolute-height ceiling. The new in-memory constructor does not remove that limit from the current on-disk store or the running QZBE node.
- A checkpoint is a trust base; competing branches below it cannot be compared without extra retained ancestry or an explicit finalization/reorg policy. No such production policy is selected here.
- No independent external CAS provider has been deployed or bound to checkpoint publication; a local record checksum is not freshness/anti-rollback protection.
- There is still no public listener, native Mainnet, production owner-key ceremony, founder transfer, real liquidity or QZXB/USDT market.

Gate 2, Gate 8, the public multi-operator devnet gate, and independent security/release gates remain open. This checkpoint is an in-memory continuation capability, not a Mainnet launch.
