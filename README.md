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
specification, signed trust scenarios, a frozen run of the C# examples, documents that must be refused, and histories
the generator signs itself, change set by change set - so that where they agree is shown, and where they differ is
written down and pinned.

## Status

Both harnesses are green against the pinned submodules (WWCP_POI `ec3dace`, WWCP_POI.TS `37b34f2`, Hermod `0fff6c9`,
Styx `f494c8cd`):

| | Vectors | Passed | Skipped |
|---|---|---|---|
| C# harness (NUnit), WWCP_POI3 | 444 | 466 tests | none |
| TypeScript harness (vitest), WWCP_POI.TS | 444 | 431 tests | 20: 7 signing from the private seeds, which WWCP_POI.TS does not do; 13 replays of what WWCP_POI.TS leaves to WWCP_POI (the references a version holds, what a model rates among them, groups of e-mobility providers, grid connection points) |

WWCP_POI.TS runs the same golden vectors in its own suite as well (`tests/conformance.test.ts`), from its vendored copy.

The two implementations agree on every vector both run. The six deviations the vectors found first, where
**WWCP_POI3 took what WWCP_POI.TS refuses**, are fixed in WWCP_POI (D1 and D2 in `2c90847`, D3 in `be07037`, D4 and
D5 in `6e469a0`, D6 in `65e658d`); D7, the other way round, where **WWCP_POI.TS took what WWCP_POI3 refuses**, in
WWCP_POI.TS `b9c786e`; D8, found by the histories the generator signs, the other way round as well, in WWCP_POI.TS
`e2b66b6`; D9, certificates WWCP_POI3 refuses to read, the other way round as well, in WWCP_POI.TS `1f0d9c7`. D10,
found by the vectors of the QI-Digital documents of example A14, WWCP_POI3's, in WWCP_POI `bbe8fb8`; D11, the
calibration certificate of a charging station compared with its own serial number, of both, in WWCP_POI in the same
commit and in WWCP_POI.TS `9153bc6`; D12, found by the vectors of EV Taler, a signing key of a party of a usage POI does
not know, WWCP_POI.TS's, in WWCP_POI.TS `37b34f2`.
Their vectors hold both implementations to it - see
**[docs/implementation-deviations.md](docs/implementation-deviations.md)**:

| | Deviation |
|---|---|
| D1 | ✅ The JSON reader for hashing takes what is no JSON (trailing commas, comments, `0x10`, a second value after the first …): fixed in WWCP_POI `2c90847` |
| D2 | ✅ A station proof may name another revision than its attestations: fixed in WWCP_POI `2c90847` |
| D3 | ✅ An attestation counts before it was signed: fixed in WWCP_POI `be07037` |
| D4 | ✅ An attestation of a subject counts for the whole proof: fixed in WWCP_POI `6e469a0` |
| D5 | ✅ The role of an attestation is not checked: fixed in WWCP_POI `6e469a0` |
| D6 | ✅ A proof's certificates and key statement may name another roaming network operator: fixed in WWCP_POI `65e658d` |
| D7 | ✅ WWCP_POI.TS: a certificate may name a hardware revision or firmware version twice, and so may the energy meters it was issued with: fixed in WWCP_POI.TS `b9c786e` |
| D8 | ✅ WWCP_POI.TS takes a change set signed, besides by its owner, by a key of a party not valid at its `createdAt`, which WWCP_POI3 refuses: fixed in WWCP_POI.TS `e2b66b6` |
| D9 | ✅ WWCP_POI.TS takes a certificate WWCP_POI3 refuses to read: for no model or for two, without a hardware revision, firmware version or release, a relative `documentURL`, an empty legislation, a `notAfter` before its `notBefore`, a release twice or both verified and compatible, energy meters of an energy meter model or one model twice (16 vectors `version-certificate-*`): fixed in WWCP_POI.TS `1f0d9c7` |
| D10 | ✅ WWCP_POI3 leaves out a text of a QI-Digital document in no language, or one that is no text, while reading it: the signature verifies, the text travels with the document unsigned; WWCP_POI.TS refuses it: fixed in WWCP_POI `bbe8fb8` |
| D11 | ✅ WWCP_POI.TS compares the calibration certificate of a charging station with its own serial number, and takes it for a station of another serial number, or of none, as WWCP_POI3 did before `bbe8fb8`: fixed in WWCP_POI.TS `9153bc6` |
| D12 | ✅ WWCP_POI.TS takes a version whose charging station operator names a signing key of a usage POI does not know, which WWCP_POI3 refuses: it read the keys of a party where it used them, not with the version: fixed in WWCP_POI.TS `37b34f2` |

D3 to D6 confirm, now with data, findings of the review WWCP_POI.TS made of the C# implementation
([`docs/csharp-review.md`](docs/csharp-review.md)), and so does D11, finding 23, which WWCP_POI.TS shares; D1, D2, D7,
D8, D9, D10 and D12 are new. Which of its 23 findings the vectors
hold, and why the rest is out of their reach, is listed in [docs/implementation-deviations.md](docs/implementation-deviations.md).
Findings 20 and 21, custom data held as given, also the custom data of an address, are fixed in Styx `06b592d3`; the
vectors `spec-2-custom-data-*` hold both implementations to it (against Styx `91901a9`, WWCP_POI3 wrote other
decimals, integers and timestamps, and dropped the custom data of an address).

## What is in here

| Directory | Content |
|---|---|
| [`test-vectors/`](test-vectors/README.md) | **The golden vectors**, generated: canonical JSON and CBOR, encodings, the examples of SPECIFICATION.md section 6 and its content with custom data, signed trust scenarios, the documents of the frozen run with what to calculate of them, refusals, histories the generator signs, replayed step by step, and the QI-Digital documents of example A14, checked as it checks them. Their format is in the [README](test-vectors/README.md) there. |
| `test-vectors/runs/csharp-33447ac/` | **The frozen run**: what the C# examples A1 to A14 of WWCP_POI `33447ac` published and MakeProofs made of the same history, public data only (WWCP_POI.TS keeps a vendored copy, next to its copy of the golden vectors). |
| [`tools/generate-test-vectors.mjs`](tools/generate-test-vectors.mjs) | The generator: Node, no dependencies. Takes every value verbatim from its source, re-derives the anchors with `node:crypto` alone (identifications, ETags of canonical JSON and deterministic CBOR, tree digests, thumbprints, signatures, the digests chaining price statements), signs the trust scenarios and the histories deterministically (Ed25519, Ed448, ES256 after RFC 6979), and refuses to write on any mismatch. |
| `Tests/WWCPPOIConformance_Tests/` | The **C# harness** (NUnit): WWCP_POI3 against every vector file, plus `VendoredCopiesTests`. |
| `Tests/WWCPPOIConformance_Tests.TS/` | The **TypeScript harness** (vitest): WWCP_POI.TS, imported from source, against every vector file. |
| [`docs/implementation-deviations.md`](docs/implementation-deviations.md) | Where the two differ, why it matters, how to fix it; what both do alike; the findings of the C# review and the vectors holding them. |
| [`docs/csharp-review.md`](docs/csharp-review.md) | The review WWCP_POI.TS made of the C# implementation while porting it, cited as *csharp-review N*: each finding, how it was established, and where it was fixed. |
| `libs/` | Git submodules: the two implementations, and Hermod and Styx below the C# one. |

## Submodules

| Submodule | Purpose |
|---|---|
| [`libs/WWCP_POI`](https://github.com/OpenChargingCloud/WWCP_POI) | Implementation under test #1, `WWCP_POI3` (C#), and the specification `SPECIFICATION.md` |
| [`libs/WWCP_POI.TS`](https://github.com/OpenChargingCloud/WWCP_POI.TS) | Implementation under test #2 (TypeScript) |
| [`libs/Hermod`](https://github.com/Vanaheimr/Hermod) | Below WWCP_POI3 |
| [`libs/Styx`](https://github.com/Vanaheimr/Styx) | Below Hermod: canonical JSON, deterministic CBOR, COSE - and its README, a source of vectors |

Hermod and Styx are pinned at the commits the RoamingHubCLI pins together with WWCP_POI (`85b3221`, with WWCP_POI
`ec3dace`): Hermod `0fff6c9`, Styx `f494c8cd`. WWCP_POI since `7862c86` needs a
Hermod that checks the origin of a request (`HTTPRequest.AllowsOrigin`). Styx keeps custom data as given since
`06b592d3` (findings 20 and 21 of the review WWCP_POI.TS made of the C# implementation), which the vectors
`spec-2-custom-data-*` cover.

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
   of the next names. The trust scenarios are signed with the same keys, deterministically. For the histories it signs,
   it first calculates of the frozen run what it calculates of them: the json and cbor ETags of every version, the
   identification of every commit, change set and checkpoint and the tree of its commits, and the input of every
   signature of the run node:crypto verifies, which must verify with its key; and ES256 against RFC 6979, A.2.5.
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
