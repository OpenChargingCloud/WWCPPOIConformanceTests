# WWCP POI Conformance Tests

[![CI](https://github.com/OpenChargingCloud/WWCPPOIConformanceTests/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenChargingCloud/WWCPPOIConformanceTests/actions/workflows/ci.yml)
[![Nightly](https://github.com/OpenChargingCloud/WWCPPOIConformanceTests/actions/workflows/nightly.yml/badge.svg)](https://github.com/OpenChargingCloud/WWCPPOIConformanceTests/actions/workflows/nightly.yml)

Conformance test suite for **[WWCP POI 3](https://github.com/OpenChargingCloud/WWCP_POI)** - authentic POI data of
roaming networks: versions and their ETags, commits, checkpoints, station proofs, attestations, key statements, trust
anchors and price statements - held to one set of **golden test vectors** by two independent implementations:

 * **[WWCP_POI](https://github.com/OpenChargingCloud/WWCP_POI)** (`WWCP_POI3`, C#/.NET), the reference implementation
   and home of the specification (`SPECIFICATION.md`), and
 * **[WWCP_POI.TS](https://github.com/OpenChargingCloud/WWCP_POI.TS)** (`@open-charging-cloud/wwcp-poi`,
   TypeScript), the verifier an EV driver's app uses.

WWCP_POI.TS calculates "byte for byte as the C# implementation calculates it". Until now that rested on one direction:
the C# examples published, the TypeScript port checked. Here both run the very same vectors - the examples of the
specification, signed trust scenarios, a frozen run of the C# examples, and documents that must be refused - so that
where they agree is shown, and where they differ is written down and pinned.

## Status

Both harnesses are green against the pinned submodules (WWCP_POI `3e32f48`, WWCP_POI.TS `20c16aa`, Hermod `fbb442f`,
Styx `91901a9`):

| | Vectors | Passed | Skipped |
|---|---|---|---|
| C# harness (NUnit), WWCP_POI3 | 268 | 286 tests | none |
| TypeScript harness (vitest), WWCP_POI.TS | 268 | 268 tests | 7: signing from the private seeds, which WWCP_POI.TS does not do |

WWCP_POI.TS runs the same golden vectors in its own suite as well (`tests/conformance.test.ts`), from its vendored copy.

The two implementations agree on 254 of the 268 vectors. On 14, **WWCP_POI3 takes what WWCP_POI.TS refuses**, four
open deviations, each marked on its vectors and pinned (D4 and D5 are fixed in WWCP_POI `6e469a0`) - see
**[docs/implementation-deviations.md](docs/implementation-deviations.md)**:

| | Deviation of WWCP_POI3 |
|---|---|
| D1 | The JSON reader for hashing takes what is no JSON (trailing commas, comments, `0x10`, a second value after the first …) |
| D2 | A station proof may name another revision than its attestations |
| D3 | An attestation counts before it was signed |
| D4 | ✅ An attestation of a subject counts for the whole proof: fixed in WWCP_POI `6e469a0` |
| D5 | ✅ The role of an attestation is not checked: fixed in WWCP_POI `6e469a0` |
| D6 | A proof's certificates and key statement may name another roaming network operator |

D3 to D6 confirm, now with data, findings of the review WWCP_POI.TS made of the C# implementation
([`docs/csharp-review.md`](https://github.com/OpenChargingCloud/WWCP_POI.TS/blob/master/docs/csharp-review.md));
D1 and D2 are new.

## What is in here

| Directory | Content |
|---|---|
| [`test-vectors/`](test-vectors/README.md) | **The golden vectors**, generated: canonical JSON and CBOR, encodings, the examples of SPECIFICATION.md section 6, signed trust scenarios, the documents of the frozen run with what to calculate of them, and refusals. Their format is in the [README](test-vectors/README.md) there. |
| `test-vectors/runs/csharp-dbf39b0/` | **The frozen run**: what the C# examples A1 to A13 of WWCP_POI `dbf39b0` published and MakeProofs made of the same history, public data only (WWCP_POI.TS keeps a vendored copy, next to its copy of the golden vectors). |
| [`tools/generate-test-vectors.mjs`](tools/generate-test-vectors.mjs) | The generator: Node, no dependencies. Takes every value verbatim from its source, re-derives the anchors with `node:crypto` alone (identifications, ETags of canonical JSON, tree digests, thumbprints, Ed25519 signatures, the digests chaining price statements), signs the trust scenarios deterministically, and refuses to write on any mismatch. |
| `Tests/WWCPPOIConformance_Tests/` | The **C# harness** (NUnit): WWCP_POI3 against every vector file, plus `VendoredCopiesTests`. |
| `Tests/WWCPPOIConformance_Tests.TS/` | The **TypeScript harness** (vitest): WWCP_POI.TS, imported from source, against every vector file. |
| [`docs/implementation-deviations.md`](docs/implementation-deviations.md) | Where the two differ, why it matters, how to fix it; what both do alike; what the vectors do not cover yet. |
| `libs/` | Git submodules: the two implementations, and Hermod and Styx below the C# one. |

## Submodules

| Submodule | Purpose |
|---|---|
| [`libs/WWCP_POI`](https://github.com/OpenChargingCloud/WWCP_POI) | Implementation under test #1, `WWCP_POI3` (C#), and the specification `SPECIFICATION.md` |
| [`libs/WWCP_POI.TS`](https://github.com/OpenChargingCloud/WWCP_POI.TS) | Implementation under test #2 (TypeScript) |
| [`libs/Hermod`](https://github.com/Vanaheimr/Hermod) | Below WWCP_POI3 |
| [`libs/Styx`](https://github.com/Vanaheimr/Styx) | Below Hermod: canonical JSON, deterministic CBOR, COSE - and its README, a source of vectors |

Hermod and Styx are pinned at the commits the RoamingHubCLI pins together with WWCP_POI, the same from `801bbce` to
`dbf39b0`.

```bash
git clone --recurse-submodules https://github.com/OpenChargingCloud/WWCPPOIConformanceTests.git
```

## Building and testing

The C# harness (requires the .NET 10 SDK):

```bash
dotnet test WWCPPOIConformanceTests.slnx
```

The TypeScript harness (requires Node.js 22.18 or newer). It imports WWCP_POI.TS **from source**, so the
implementation's own dependencies have to be installed as well - Node resolves them from `libs/WWCP_POI.TS/node_modules`:

```bash
npm --prefix Tests/WWCPPOIConformance_Tests.TS install
```

```bash
npm --prefix libs/WWCP_POI.TS ci
```

```bash
npm --prefix Tests/WWCPPOIConformance_Tests.TS test
```

The drift guard (requires Node.js; only `libs/WWCP_POI` and `libs/Styx` are read):

```bash
node tools/generate-test-vectors.mjs --check
```

Regenerating after a change of the generator, and refreshing the vendored copy inside WWCP_POI.TS:

```bash
node tools/generate-test-vectors.mjs --mirror libs/WWCP_POI.TS/tests/vectors
```

(then commit WWCP_POI.TS first, and bump its pin here).

## How the vectors stay trustworthy

1. Every value is taken verbatim from its source - SPECIFICATION.md, the Styx README and tests, the frozen run - and
   the generator refuses to write when a source no longer says it.
2. Before writing, the generator re-derives the anchors with `node:crypto` alone, an independent third look: the
   identifications and ETags of section 6, the tree digests, the key thumbprints, every Ed25519 signature of section 6
   (signing again from the private seeds), and the digest of every price statement of the run, which the `previous`
   of the next names. The trust scenarios are signed with the same keys, deterministically.
3. Both harnesses run every vector; a vector enters only when two implementations agree on it, or carries the
   `knownDeviations` of the one that does not, and that harness holds its implementation to the deviation.
4. CI gates the pinned submodules: the drift guard, the C# harness on Windows and in a bare Debian 13 container (where
   the C# implementation runs in production), the TypeScript harness on Ubuntu and Windows.
5. The nightly run advances all submodules to their upstream HEADs and runs the drift guard and both harnesses again -
   a red night with a green CI means an upstream master calculates or accepts otherwise than the vectors say, or
   SPECIFICATION.md moved without them. And, informational, it runs the C# examples of WWCP_POI master anew and checks
   what they publish with WWCP_POI.TS - the interop check that moved here from WWCP_POI.TS's own nightly.

## License

[GNU Affero General Public License v3.0](LICENSE), as WWCP_POI and WWCP_POI.TS.

Copyright 2014-2026 GraphDefined GmbH
