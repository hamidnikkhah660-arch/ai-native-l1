# CP-0411 - Bounded Body-Aware QZBE v2 Candidate Miner

Date: 2026-10-26

Status: **local candidate engineering; not integrated into the canonical node; not approved for public or value-bearing use**

## Purpose

CP-0410 changed QZBE consensus identity so the proof-of-work and fork-choice digest commits to both the memory-hard header digest and the canonical QZB4 v2 execution-body ID. A nonce must therefore be found against the final body-bound digest, not only the header digest or a permissive MAX target.

## Candidate mining API

V04ExecutionForkChoiceCandidate::mine_candidate_on:

- builds one execution body on a selected known parent and derives the target through the existing parent-branch target-history logic;
- requires an explicit attempt budget from 1 through MAX_QZBE_MINING_ATTEMPTS (currently 256);
- checks a caller-supplied cancellation predicate before every memory-hard hash;
- varies the PoW nonce with checked arithmetic and computes the same qzbe_pow_digest used by consensus verification;
- returns only a candidate that passes the normal decode and PoW verification path; and
- does not mutate the fork-choice graph. The caller must still submit the returned bytes through the ordinary validation/commit route.

Exhaustion, cancellation, invalid attempt budgets, and nonce overflow fail explicitly. The per-call attempt cap bounds work; callers must additionally apply wall-clock and resource policy. This is a candidate API, not a service or network miner.

## Offline smoke change

The offline-only qzbe_v04_candidate_smoke now uses the body-aware bounded miner. Its diagnostic target is deliberately easy but non-MAX ([0xEF; 32]) so the smoke exercises real target comparison. The PoW memory setting remains 8 MiB only for this offline diagnostic. These are not proposed mainnet or public-testnet parameters.

The smoke remains explicitly offline: P2P, RPC, wallet and market listeners are disabled; transaction submission and mainnet issuance are disabled; the configured authenticator rejects every transaction; Genesis, network ID, and issuance schedule are explicit inputs; and the temporary test directory is removed after verification.

## Regression coverage

- bounded_miner_finds_body_bound_pow_under_a_non_max_target: finds a valid body-bound digest for a non-MAX target and confirms ordinary insertion accepts it without the mining call mutating the graph.
- bounded_miner_honors_cancellation_attempt_limits_and_exhaustion: checks zero and over-cap budgets, cancellation, bounded-search exhaustion, and absence of partial graph mutation.
- All six qzbe_v04_candidate_smoke binary tests pass after the smoke was switched to the body-aware miner.
- Manual offline persistence/restart smoke passed against one unique temporary data directory: height 0 to 3, then after close/reopen height 3 to 5. Both runs reported PASS and replayed state roots; all network/service listeners remained disabled, and the temporary directory was removed.

Validation passed on this working tree: cargo fmt --all -- --check; cargo check --all-targets --locked --offline; cargo test --all-targets --locked --offline with 830 library tests, both node harnesses 36/36, the QZBE smoke binary 6/6, and all other targets passing with zero failures. The manual offline 0-to-3 then reopen-and-resume 3-to-5 smoke also passed. Fresh GitHub CI has not yet run for CP-0411.

## Remaining blockers

The candidate miner has no connection to the canonical node producer or peer network. It does not by itself provide mempool selection, authenticated peer transport, signed transaction submission, production resource governance, externally operated CAS, independently protected anti-rollback state, or a validated economic profile. The non-MAX smoke target and reduced memory are diagnostic values only.

Next work: complete exact-tree all-target validation, publish a separate reviewable follow-up, then design and test the dedicated zero-value development-node runtime with QZB4/QZBE wired across block production, import, fork choice, persistence/replay, peer authentication and transaction admission. Independent operator/provider/security review and explicit legal/economic launch gates remain mandatory before any public or value-bearing launch.

No external team or auditor has been contacted or engaged through this work; no email has been sent, no merge occurred, and no public network or value-bearing issuance has been launched.