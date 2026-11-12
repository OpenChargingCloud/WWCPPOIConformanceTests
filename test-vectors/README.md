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
| `poi-history.json` | `runs/csharp-76d3653`, the frozen run | Documents of the run and what an implementation must calculate of them: `versions` (ETags), `commits`, `checkpoints` (identifications and fields), `checkpointProofs`, `priceStatements` (digests, chains), `trustAnchors`, `stationProofs` (root, verified against the trust anchor at `at`), `replays` (the history commit by commit). |
| `poi-refusals.json` | the frozen run; SPECIFICATION.md | `vectors`: a document of the run with a JSON patch applied, checked at another time, against another trust anchor or checkpoint, or a text: each must be refused. |
| `poi-histories.json` | SPECIFICATION.md sections 4, 5, 8.5, 10 and 11; histories the generator signs | `histories`: small histories of the roaming network `rn1` of section 6, made and signed by the generator, their documents as JSON text. `replays`: a history taken step by step, `accepted`, or its last step `refused`, with its `control`. `anchoredSnapshots`: a history started from a snapshot of another server, of the head or of a checkpoint, only anchored in the trust anchor at `at` (10.5, Anchored), with its `control`. |
| `poi-qidigital.json` | example A14 of WWCP_POI and `WWCP_POI3/RoamingNetwork/QIDigital`; the frozen run | `vectors`: the QI-Digital documents example A14 published - two digital certificates of conformity, a declaration of conformity, a calibration certificate - each checked as example A14 checks it, against QA (`verify`), against a certificate it names (`certificate`) or covering a meter (`cover`), `accepted` or `refused` with its `control`. |
| `poi-verifier.json` | the README of WWCP_POI.TS 0.2.0 (experimental) and `WWCP_POI3/Verifier` of WWCP_POI; `runs/chargy-fc513cd`, the fixtures of ChargyWebApp | `vectors`: the verifier extensions of WWCP_POI.TS 0.2.0, which WWCP_POI3 has as well, each a `kind` of check with its inputs as documents of the fixtures and what both give of it (`result`, normalized), `accepted`, or `refused` with its `control`, the `reason` both name and what it `changes`. |

## The frozen run

`runs/csharp-76d3653/` is what one run of the C# examples A1 to A16 of WWCP_POI at commit `76d3653` published (public
data only; its console output is `csharp-output.log`), and in `proofs/`, what `proofs/MakeProofs.cs.txt` made of the
same history with the C# implementation, at `at`. It replaces `csharp-c4c3c5a`, since `76d3653` refuses a charging
pool naming the payment option `EVTaler` without the authentication mode `SecureDynamicQRCode` (decision D8): Jena
Paradies, revision 11 of epoch 2, names both now, `{ "type": "SecureDynamicQRCode", "channels": [ "Display" ] }`; the
head of epoch 2 stays revision 11. `csharp-c4c3c5a` had replaced `csharp-045e180`, since example A16 charges a session
of DE*GEF*E1*1 by EV Taler in two steps (`driver/evidence-DE_GEF_E1_1-evTaler.json`: its station proof, no
checkpoints, and a price statement, whose digest `poi-history.json` calculates); the head of epoch 2 stays revision
11. `csharp-045e180` had replaced `csharp-33447ac`, since `045e180` identifies a
transparency software release under its manufacturer and a certificate under the body issuing it
(`GraphDefined:chargy-1.5.0`, `PTB:2026-0017`, `PTB:2026-0042`; POI3-ISSUES.md S36), which a version of
`csharp-33447ac` is refused for, and example A15 gives DE*GEF its EV Taler merchant
(`published/QA-DE-GEF-E1-1-evTaler-proof.json`): the head of epoch 2 is revision 11, which
`proofs/QA-epoch-2-commits-to-head.json` goes on to - `QA.json` and `QA-commit.json` stay revision 8, the head
examples A13 and A14 left. `csharp-33447ac` had replaced `csharp-987fa26`, since example A14 publishes the
QI-Digital documents of a meter (`published/EM-LAB-DCC-2026-0815.json`, `PTB-DE-26-M-PTB-0108.json`,
`PTB-DE-26-QS-PTB-0042.json`, `SAALE-DoC-SM-3-2026-01.json`) and adds the calibration laboratory EM-LAB to QA, so that
the head was revision 8 of epoch 2; `csharp-987fa26` had replaced `csharp-80e4ccc`, since `987fa26` gave models,
stations, meters and certificates hardware revisions and firmware versions, and certificates for station and meter
models with their components (docs/csharp-review.md, 16 and 17). WWCP_POI.TS keeps a vendored copy of it, of
`runs/chargy-fc513cd` and of the `poi-*.json` for its own suite (`tests/conformance.test.ts`); `VendoredCopiesTests` of the C# harness fails when a copy drifts. Every
run of the examples makes new keys, so every digest of another run differs: this run is frozen, not regenerated.

`poi-history.json` names `at`, a point in time at which its key statements, keys and the attestations of its station
proofs are valid. A document is named by `file` (relative to the run) and `pointer`, a JSON pointer (RFC 6901) into
it, `""` for the whole file.

## The fixtures of ChargyWebApp

`runs/chargy-fc513cd/` holds what ChargyWebApp at commit `fc513cd` has in `tests/fixtures/POISession`, `POIHistory`,
`POIPrices`, `POIPublication` and `POITrustTransitions`, byte for byte: the documents of the verifier extensions of
WWCP_POI.TS 0.2.0, which WWCP_POI3 has since WWCP_POI `89d2e02` (`WWCP_POI3/Verifier`) - the key of the meter of an
EVSE, historical meter evidence, prices bound to a session, receipts of witnesses, trust transitions, the keys a CPO
signs its documents with. SPECIFICATION.md names only the usages `chargeTransparencyRecords` and
`witnessPublications`; both implementations call the rest experimental. The generators of ChargyWebApp
(`build-tools/generatePOI*.mjs`) made them with WWCP_POI.TS itself, with keys of public seeds (Ed25519 41 to 44 and
others, ML-DSA-65) and the published P-256 test key of a meter, whose ECDSA signatures differ every time: the fixtures
are frozen, not regenerated. Each directory keeps its `README.md`, which says what each counterexample is, and its
`provenance.json`, with the hashes of its files.

Seven of them are the vector files WWCP_POI.TS 0.2.0 (`tests/vectors`) and WWCP_POI3 (`WWCP_POI3_Tests/Vectors/TS`)
share, byte for byte: `history-session.json` is `POIHistory/archived-session.chargy`, `history-witnesses.json`
`POIHistory/trusted-witnesses.json`, `session-price-ed.json`, `-pqc.json` and `-decimal.json` are
`POIPrices/session-with-price.chargy`, `pqc-price.chargy` and `decimal-price.chargy`, `price-publication.json` is
`POIPublication/vectors.json`, `trust-transitions.json` `POITrustTransitions/vectors.json`. Their `meter-session.json`
is of an older run of ChargyWebApp (`97da24d`), not of this one.

## The documents the generator makes (`chargy/`)

`chargy/` holds documents of the verifier extensions the generator makes itself (its section 9a), GENERATED like the
vector files and drift guarded by `--check`, never frozen: deterministic, they are the same bytes every time.
`chargy/POIPrices/` are the cases of `POIPrices` of ChargyWebApp, made as its `build-tools/generatePOIPriceExample.mjs`
made them, of the same public seeds, on `POIHistory/archived-session.chargy` of the run - but the readings of the meter
are signed by an ES256 key of a seed of the generator (RFC 6979), not by the published test key, and two counterexamples
show what their README says: `foreign-tariff.chargy` a tariff of the pattern `{operatorId}*T{suffix}` none of the
references of the EVSE names (`DE*POI*T2`), `conditional-price.chargy` an element restricted by `maxEnergy`. Each case is
anchored first: made with the readings of its fixture, it is that fixture, as canonical JSON. `pqc-price.chargy` is not
made here (node:crypto signs ML-DSA-65 with randomness). Each set has its `README.md` and `provenance.json`, written by
the generator. ChargyWebApp may vendor them, as WWCP_POI.TS does (`--mirror`).

Before anything is taken of them, the generator checks with `node:crypto` alone what they claim (its section 9): the
hashes of their provenance and that the shared copies are the same bytes; every signature over its input - key
statements, certificates, attestations, checkpoints of the operator and of witnesses, price statements in Ed25519 and
ML-DSA-65, agreements, receipts, both sides of a trust transition -; the OCMF readings with the key of their container;
the identifications of checkpoints and commits, the root of every proof of a station, the inclusion of a commit and of
a price statement in a checkpoint, the identification of a meter key, the digest of the start document an agreement
binds, the statement, its SHA-256 and the tariff a receipt binds, the policy identity and the key statement a trust
transition continues. What does not hold is exactly what the READMEs name broken; anything else stops the generator.

A vector of `poi-verifier.json` names a `kind`, the check, and its inputs; a document is `file` (relative to the run)
and `pointer`, read on into a string, which is a JSON document of its own (a fixture keeps signed decimals so); a
document the generator makes names its directory as well, `documents` (`"chargy"`: `file` relative to `chargy/`). `trust`
is the local trust a verification starts from: the QR code of a trust anchor (`anchor`), a key statement
(`keyStatement`), every identity key of the anchor trusted, at `at`, as a context of now (`current`) or of a key
statement saved before (`historical`). `result` is what both implementations give, normalized - identifications, the
words of the verdicts, counts:

| `kind` | Check | `result` |
|---|---|---|
| `meterKey` | the key of the meter of an EVSE a station proof gives (`proof`, `request`: EVSE, serial number, key format, a key by its identification) | the station, meter and serial number, `keyId`, `keyIdScheme`, `canonicalKeyId` (the COSE thumbprint), `association` |
| `historicalMeterEvidence` | the keys of a meter at the signed times of its readings (`evidence`, `request` with `measurementTimes`, `policy`: trusted witnesses of checkpoints, how many required) | `bindings` (meter, key, association), the `publications` of each version, `independentTime` |
| `sessionPrice` | a price bound to a session (`evidence`, `request`: EVSE, serial number, `chargingStarted`, the SHA-256 of the start document; `policy`: a `publicationPolicy` of witnesses the verifier accepted) | the verdicts `signatures`, `agreement`, `applicability`, `publication`, `publicationBeforeStart`, `customerConsent`, `witnessedBy`, the `selected` statement (digest, algorithm, energy price as written), the `organizations` that witnessed it |
| `trustTransition` | a transition (`transition`) of the operator `operator`, accepted at `acceptedAt` as `sequence` | `requiredConsensus`, how many holders signed of the old and of the next quorum, the policy identity of the next anchor, the epoch |
| `chargingDocumentKeys` | the keys a CPO signs its documents with, of a station proof (`request`: EVSE, operator, `at`) | the station, the keys (identification, algorithm) |
| `publicationReceipt` | a receipt of a witness read alone (`receipt`) | its `digest`, which the generator calculates as well |
| `trustPolicyId`, `keyStatementDigest`, `offerHashes` | calculated alone: the policy identity of a trust anchor, the digest of a key statement, what a receipt binds of a statement and a tariff | the value, which the generator calculates as well |

A `refused` vector has no `result`. Its `control` is the same check, of what the refusal is about given otherwise -
the document the counterexample changes, the request or policy as the accepted case has it -, which both take first;
`reason` is what both name, where they word it alike (WWCP_POI3 ends it with "!"). `changes` are the JSON pointers in
which the case differs from its control, all of them; where a document of the run is another one (a `file` or
`pointer` among the changes), `documentChanges` are prefixes covering every pointer in which that document differs,
each of one at least - the serial number of a meter and the attestations signed again over it, say. The generator
calculates both and stops where a vector claims otherwise, so a refusal cannot be of something its control already has.

## Common fields

- `id`: stable, never reused. `description`: what the vector shows.
- `source` / `basis`: where the specification (or Styx, an RFC) says so. `(proposed)` marks a rule the specification does
  not state yet, taken from a review finding.
- `knownDeviations`: implementations known to do otherwise, by name - `wwcp-poi3` (C#), `wwcp-poi.ts` (TypeScript).
  The harness of a named implementation holds it to its deviation (the opposite outcome: taken where the vector refuses,
  refused where it takes, another result than its `result`), so that a fix turns it red; `deviation` links the analysis
  in `docs/implementation-deviations.md`.
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
| `version` | the roaming network is read as WWCP_POI3 reads it: the `eTags` it lists are those of its content, every entity and value as it reads them, as the content holds them, the references among them, no identification twice that is unique within the roaming network, no two offers of an operator overlapping (9.4), the time zone of a charging pool or template one of a region of the IANA time zone database the reader knows (9.4), the public keys of energy meters as BouncyCastle makes them | |
| `checkpointProof` | the commit proof verifies against the checkpoint | `checkpoint` |
| `stationProof` | the station proof verifies against the trust anchor at `at` | `trustAnchor` (a file of the run), `at` |
| `priceStatement` | the price statement verifies with the signing keys of its charging station operator | `keysFrom` (the version) |
| `entityPriceStatement` | the price statement is taken against the roaming network as it names its entity (12.1), by the route each implementation has: a history started from `snapshot` takes it at `at` (a server), a client takes it with the proof of its station `stationProof`, verified against `trustAnchor` at `at` | `snapshot`, `stationProof`, `trustAnchor`, `at` |
| `checkpointPriceStatements` | the price statements `priceStatements` are those the checkpoint names, no two of one entity, in any spelling, and sequence that differ (12.3): taken along with it by a history started from `snapshot` of its commit, its signatures unchecked, or checked against it | `priceStatements` (with its own `patch`), `snapshot` |
| `trustAnchor` | the text of a QR code is read | `text` |

`document` gives the document: `file`, `pointer`, and `patch`, a JSON patch (RFC 6902; `add`, `replace`, `remove`). A
harness checks the unpatched document first, the control, so that a refusal is the patch's doing; of a
`checkpointPriceStatements`, the checkpoint and its `priceStatements` as published. `reason`, where a vector gives it,
is a text the refusal names, as both implementations word it: a harness checks that it does, so that the vector is
refused for what it is about.

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
  every signature are checked against the profiles of the epoch. `requiredSignatureRoles`, where given, are the roles
  every commit of the replay must be signed in, by a key the version it leads to lets sign in it (SPECIFICATION.md 5.4,
  POI3-ISSUES.md S24): `RequiredSignatureRoles` of `TryAppend` of WWCP_POI3, `requiredSignatureRoles` of the options of
  a history of WWCP_POI.TS - a harness ignoring it takes what such a replay refuses.
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
