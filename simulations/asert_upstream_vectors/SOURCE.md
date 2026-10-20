# Official ASERT upstream test vectors

Source directory: https://download.bitcoincashnode.org/misc/data/asert/test_vectors/
Specification: https://bitcoincashnode.org/2020-11-15-asert/

These are unmodified public aserti3-2d test-vector files downloaded on 2026-10-11 from the official Bitcoin Cash Node vector directory. The files are embedded by the Rust candidate's unit tests with `include_str!`; tests require exactly 14,000 rows across the twelve runs and compare every emitted compact target bit pattern. The original comment headers are preserved. Do not edit these files to make a local test pass.

| File | Cases | Bytes | SHA-256 |
|---|---:|---:|---|
| run01 | 10 | 441 | `bfdbac6a3eb2ffaeecb8475ab7be4de61b780f1abc2ad858846a44d69d4a496e` |
| run02 | 10 | 462 | `0db6f9bc26a3bb29a06ea2dec44606803c76aca8b903de0658e1cd40c00efc7d` |
| run03 | 10 | 456 | `a21049dca0426086d4bc399ad962861e7e032f22a89e0bf7da8d0e1f99c7b790` |
| run04 | 225 | 6,314 | `3d195813853c758920d49ce54e0d2048b5dbf66264d669a200c0b5b66138e025` |
| run05 | 225 | 5,328 | `02d8a492d91f166fad424391830f8921de650f9820483300f8c90ba72a67238a` |
| run06 | 1,000 | 25,895 | `12a0f7672327cf8887367cf93ed22c36ae1c3778352e922de771af15496812fe` |
| run07 | 1,000 | 25,066 | `8dae763a095cfe8ab6721e0bad23d433a4596ed8b0a9d9db9bc551c73be64111` |
| run08 | 500 | 13,336 | `7d19ee783dea42989d4a2d3ddf475a8c26e1f31fc1b517d348a4e3f7e6ec8403` |
| run09 | 10 | 649 | `430d771c8c6c853e0aa8190e049826add47f517dfb9898a2bf0b5c7a3280c717` |
| run10 | 10 | 794 | `34dff0a33085043626be6f1290a4089e18bd037010084b37bc67f14141121621` |
| run11 | 1,000 | 25,679 | `f912d4fb2edcf65037fa7e8c279c49a291e8e74ce507b15b3478146fe653ad88` |
| run12 | 10,000 | 259,243 | `897418f85dcb17814ea7b7556547565271c524723ece8af8d47fab4bdc0ab179` |
| **Total** | **14,000** | **363,663** | |

Coverage includes steady blocks at the PoW limit, arbitrary and minimum targets, repeated half-life schedule shifts, deterministic randomized solve times, height boundary cases, negative timestamps and a long descending-time sequence. The repository test checks the exact target bits for every data row.

This proves conformance only for the target function and target compact conversion represented by those upstream vectors. It does not prove our chain’s anchor-selection policy, timestamp validation/MTP, chain reorganization wiring, independent-client interoperability beyond this local test, or overall network security. Those remain separate gates.
