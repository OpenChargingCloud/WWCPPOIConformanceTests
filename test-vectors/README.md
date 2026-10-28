# Golden test vectors of WWCP POI 3

Language-neutral vectors that every implementation of [WWCP POI 3](https://github.com/OpenChargingCloud/WWCP_POI) runs:
the C# implementation (WWCP_POI3) and the TypeScript port (WWCP_POI.TS) in this repository, any other by reading
these files.

**Generated, never edited by hand.** `tools/generate-test-vectors.mjs` writes `poi-*.json` from their sources and
refuses to write when a source no longer says what a vector takes from it, or when one of the anchors it re-derives
with `node:crypto` alone mismatches. `--check` is the drift guard of CI. The files are kept byte for byte
(`.gitattributes`: `-text`).

| File | Source | What it holds |
|---|---|---|
| `poi-canonical-json.json` | Styx `Illias/JSON/README.md` (section 4) and its escaping table; SPECIFICATION.md section 1; RFC 8259 | `vectors`: JSON text, its canonical JSON and its deterministic CBOR (hex). `invalidInputs`: JSON text a reader must refuse, with `expectedError` (`decimalOutOfRange`, `duplicateProperty`, `syntax`). |
| `poi-encodings.json` | RFC 4648, RFC 9285 | `base64`/`base64Invalid`: canonical Base64 as POI reads keys and signature values; `base45`/`base45Invalid`: Base45, as the QR code of a trust anchor holds its CBOR. |
| `poi-specification.json` | SPECIFICATION.md section 6, every value verbatim; section 2 for custom data | `contents` (content, ETags; also the content of section 6 with custom data, held as given, its ETags calculated by the generator), `skeletons` (skeleton, digest), `commits` (commit, content, identification), `keys` (COSE key, thumbprint), `signatures` (input, value, key, private seed) and `invalidSignatures`, `priceStatements` (statement, digest), `trustAnchors` (JSON, QR code). |
| `poi-trust.json` | SPECIFICATION.md sections 8.4 to 8.6 | `stationProofs`: proofs of the example network of section 6, its operator holding the quorum of section 6, signed with its Ed25519 keys: trust anchor and proof (JSON text), the time `at`, the `root` the proof leads to, and `expected` `accepted` or `refused`. |
| `poi-history.json` | `runs/csharp-33447ac`, the frozen run | Documents of the run and what an implementation must calculate of them: `versions` (ETags), `commits`, `checkpoints` (identifications and fields), `checkpointProofs`, `priceStatements` (digests, chains), `trustAnchors`, `stationProofs` (root, verified against the trust anchor at `at`), `replays` (the history commit by commit). |
| `poi-refusals.json` | the frozen run; SPECIFICATION.md | `vectors`: a document of the run with a JSON patch applied, checked at another time, against another trust anchor or checkpoint, or a text: each must be refused. |
| `poi-histories.json` | SPECIFICATION.md sections 4, 5, 8.5, 10 and 11; histories the generator signs | `histories`: small histories of the roaming network `rn1` of section 6, made and signed by the generator, their documents as JSON text. `replays`: a history taken step by step, `accepted`, or its last step `refused`, with its `control`. `anchoredSnapshots`: a history started from a snapshot of another server, of the head or of a checkpoint, only anchored in the trust anchor at `at` (10.5, Anchored), with its `control`. |
| `poi-qidigital.json` | example A14 of WWCP_POI and `WWCP_POI3/RoamingNetwork/QIDigital`; the frozen run | `vectors`: the QI-Digital documents example A14 published - two digital certificates of conformity, a declaration of conformity, a calibration certificate - each checked as example A14 checks it, against QA (`verify`), against a certificate it names (`certificate`) or covering a meter (`cover`), `accepted` or `refused` with its `control`. |

## The frozen run

`runs/csharp-33447ac/` is what one run of the C# examples A1 to A14 of WWCP_POI at commit `33447ac` published (public
data only; its console output is `csharp-output.log`), and in `proofs/`, what `proofs/MakeProofs.cs.txt` made of the
same history with the C# implementation, at `at`. It replaces `csharp-987fa26`, since example A14 publishes the
QI-Digital documents of a meter (`published/EM-LAB-DCC-2026-0815.json`, `PTB-DE-26-M-PTB-0108.json`,
`PTB-DE-26-QS-PTB-0042.json`, `SAALE-DoC-SM-3-2026-01.json`) and adds the calibration laboratory EM-LAB to QA, so that
the head is revision 8 of epoch 2; `csharp-987fa26` had replaced `csharp-80e4ccc`, since `987fa26` gave models,
stations, meters and certificates hardware revisions and firmware versions, and certificates for station and meter
models with their components (docs/csharp-review.md, 16 and 17). WWCP_POI.TS keeps a vendored copy of it and of the `poi-*.json` for
its own suite (`tests/conformance.test.ts`); `VendoredCopiesTests` of the C# harness fails when a copy drifts. Every
run of the examples makes new keys, so every digest of another run differs: this run is frozen, not regenerated.

`poi-history.json` names `at`, a point in time at which its key statements, keys and the attestations of its station
proofs are valid. A document is named by `file` (relative to the run) and `pointer`, a JSON pointer (RFC 6901) into
it, `""` for the whole file.

## Common fields

- `id`: stable, never reused. `description`: what the vector shows.
- `source` / `basis`: where the specification (or Styx, an RFC) says so. `(proposed)` marks a rule the specification does
  not state yet, taken from a review finding.
- `knownDeviations`: implementations known to do otherwise, by name - `wwcp-poi3` (C#), `wwcp-poi.ts` (TypeScript).
  The harness of a named implementation holds it to its deviation (the opposite outcome), so that a fix turns it red;
  `deviation` links the analysis in `docs/implementation-deviations.md`.
- `notApplicable`: implementations the vector does not apply to; their harness skips it.
- `requires`: capabilities an implementation needs to run the vector, e.g. `signing` (the C# implementation signs,
  the TypeScript port only verifies). A harness skips a vector requiring a capability it lacks, and fails on a
  capability it does not know: the vector files are then newer than the harness.

## Reading the documents

Everything that is hashed is read as SPECIFICATION.md section 1 requires: numbers with a fraction as decimals,
keeping their scale; strings as strings, never as points in time; an object naming a property twice refused. The
documents of `poi-trust.json` and the inputs of `poi-canonical-json.json` and `poi-specification.json` are JSON
**text** for that reason. The `value` of a patch is small JSON - integers, strings, a decimal like `0.01`, and objects
and arrays of them - that every reader takes exactly.

## Refusals and their kinds

A vector of `poi-refusals.json` names a `kind`, what is checked:

| `kind` | Check | Also given |
|---|---|---|
| `commit` | the commit is read: its `@id` the digest of its content, ETags in hex | |
| `checkpoint` | the checkpoint is read: its `@id` the digest of its content | |
| `version` | the roaming network is read: the `eTags` it lists are those of its content, and it names no identification twice that is unique within the roaming network | |
| `checkpointProof` | the commit proof verifies against the checkpoint | `checkpoint` |
| `stationProof` | the station proof verifies against the trust anchor at `at` | `trustAnchor` (a file of the run), `at` |
| `priceStatement` | the price statement verifies with the signing keys of its charging station operator | `keysFrom` (the version) |
| `trustAnchor` | the text of a QR code is read | `text` |

`document` gives the document: `file`, `pointer`, and `patch`, a JSON patch (RFC 6902; `add`, `replace`, `remove`).
A harness checks the unpatched document first, the control, so that a refusal is the patch's doing. `reason`, where a
vector gives it, is a text the refusal names, as both implementations word it: a harness checks that it does, so that
the vector is refused for what it is about.

## Histories the generator signs

The keys of the frozen run are random and private: nothing of it can be changed and signed anew. `poi-histories.json`
holds histories `tools/generate-test-vectors.mjs` makes itself (its section 7), of the roaming network `rn1` and its
operator `DE*RNO` with the quorum of SPECIFICATION.md section 6, and of parties with keys of seeds of their own:
Ed25519 and Ed448 sign deterministically, ES256 with the nonces of RFC 6979, so regenerating changes no byte. What the
generator calculates of them - deterministic CBOR, the effective tree, identifications, signature inputs, ES256 - it
first calculates of the frozen run and of RFC 6979, against what is written there, and refuses to write on a mismatch.

- `histories`: `id`, `description`, and `documents`, JSON text by name: `genesis`, a snapshot (`{commit, roamingNetwork}`)
  of revision 0, then commits and checkpoints, to be read as POI reads JSON.
- `replays`: `history` names the history, `steps` its documents, as the replay of `poi-history.json` names files of the
  run: `fromSnapshot`, `append`, `takeCheckpoint` with `document`, `startNextEpoch` with the `genesisCommitId` every
  implementation makes of the final checkpoint, `expectHead`. Commit and checkpoint signatures are taken unchecked
  (`commitAndCheckpointSignatures`); the signatures of change sets are their owners' and checked, and the algorithms of
  every signature are checked against the profiles of the epoch.
- `expected`: `accepted` takes every step. `refused` takes every step but the last, which it refuses; and takes
  `control` in place of the last one, a document of the history refused but for what the replay is about, so that the
  refusal is that document's doing. `reason`, where given, is a text the refusal names: as both implementations word
  it, or, of a replay one implementation does not apply to (`notApplicable`), as the one it applies to words it.
- `anchoredSnapshots`: a server or client starting a history from another server (SPECIFICATION.md 10.5, Anchored).
  `document` names a snapshot among the documents of `history`: of the head (`snapshot: "head"`, `{commit,
  roamingNetwork, attestations?}`), taken only when the attestations it carries attest its head as a proof of its root
  is verified (8.4 to 8.6), or of a checkpoint (`"checkpoint"`, `{commit, roamingNetwork, checkpoint}`), taken only when
  the checkpoint is signed in the role `roamingNetworkOperator` as the trust anchor and the key statement of its version
  require. `trustAnchor` is JSON text, `at` the time the keys and attestations must be valid at. The other signatures of
  commits and checkpoints are taken unchecked (`commitAndCheckpointSignatures`). `expected` is `accepted` or `refused`;
  a refusal has a `control`, `{document, trustAnchor, at}` with what the vector is about given otherwise, which is
  taken, and `reason` as of a replay.

`poi-qidigital.json` (a proof of concept of WWCP_POI3, no part of SPECIFICATION.md; example A14 says what is checked):

- `kind`: `certificateOfConformity`, `declarationOfConformity` or `calibrationCertificate`; `document` a document of the
  run with a JSON patch (`{file, pointer, patch}`), or JSON text (`{text}`) where the text of a number matters, read as POI
  reads JSON. A refusal while reading it is a refusal.
- `check`: `verify` the document against the roaming network `network` (QA of the run, patched; a patched one leaves out
  its `eTags`) at `at`: its issuer, signing key, validity and what it names; `certificate` the declaration against the
  certificate of conformity `certificate` (no signature is looked at, the certificate's own check tells whether it is
  valid); `cover` the certificate of conformity covering the energy meter of the EVSE `evseId` of
  `chargingStationOperatorId`, as `network` names it at runtime. These other inputs must read: if one does not, the
  harness fails.
- The keys of the run are private: what needs a valid signature over other content, a patched QA gives instead. The
  one document signed anew, a calibration certificate of the charging station `DE*GEF*S2` (`qid-calibration-station*`),
  is the one of the run patched, signed by the generator with an Ed25519 key of a seed of its own for certificates, which
  QA patched gives EM-LAB. `expected` is `accepted` or `refused`; a refusal has a `control`, the same check of the
  documents of the run against QA as published at `at` - of the certificate of the station, against QA with its key and
  the station of its serial number -, which is taken, and `reason` as of a replay. The generator verifies the signature
  of each document over its input as WWCP_POI3 writes it (its context, content and signature without the value,
  canonical JSON) before it writes a vector.

## Adding vectors

Add them to the generator, with a fresh `id`, run it, and make sure both harnesses run them (or mark `requires` /
`notApplicable` deliberately). A vector enters only when at least two implementations agree on it - the generator's
anchors and one harness, at the least - or carries the `knownDeviations` of the one that does not. A change of what a
vector file holds touches three harnesses: the C# one and the TypeScript one of this repository, and
`tests/conformance.ts` with `tests/conformance.test.ts` of WWCP_POI.TS, which vendors the files.
