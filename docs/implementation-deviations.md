# Where WWCP_POI3 and WWCP_POI.TS differ

What running both implementations against the golden vectors of this repository found: where the C# implementation
(WWCP_POI3, `libs/WWCP_POI` at `2c90847`, Hermod `fbb442f`, Styx `91901a9`) and the TypeScript port (WWCP_POI.TS,
`libs/WWCP_POI.TS` at `b9c786e`) take or calculate different things.

Each deviation is

- **marked on its vectors** (`knownDeviations` and `deviation`, written by `tools/generate-test-vectors.mjs`), and
- **pinned**: the harness of the implementation that deviates holds it to its deviation, so the day it is fixed, that
  harness turns red with the message to remove the marker in the generator. A deviation can not be fixed unnoticed,
  nor come back unnoticed.

A fixed deviation keeps its section, marked ✅ with the commit that fixed it; its vectors then hold both implementations
to what they say.

Every deviation below is **demonstrated**: a vector shows it, run by both harnesses. Where it confirms a finding of the
review WWCP_POI.TS made of the C# implementation while porting it ([`csharp-review.md`](csharp-review.md), cited
as *csharp-review N*), it says so. Findings there that read the code only are now shown with data.


## Summary

| | Deviation | Who deviates | Vectors | Severity | csharp-review |
|---|---|---|---|---|---|
| [D1](#d1-lenient-json) | ✅ The JSON reader for hashing takes what is no JSON: trailing commas, comments, single quotes, unquoted names, `01`, `0x10`, raw control characters, a second value after the first: **fixed** in WWCP_POI `2c90847` | WWCP_POI3 | 9 of `poi-canonical-json.json` | medium (interop) | new |
| [D2](#d2-proof-revision) | ✅ A station proof may name another revision than its attestations: **fixed** in WWCP_POI `2c90847` | WWCP_POI3 | `stationProof-revision` | low | new |
| [D3](#d3-future-attestation) | ✅ An attestation counts before it was signed: **fixed** in WWCP_POI `be07037` | WWCP_POI3 | `stationProof-before-signed`, `trust-future` | medium | 7 |
| [D4](#d4-subject-attestation) | ✅ An attestation of a subject counts for the whole proof: **fixed** in WWCP_POI `6e469a0` | WWCP_POI3 | `trust-subject` | medium | 6 |
| [D5](#d5-attestation-role) | ✅ The role of an attestation is not checked: **fixed** in WWCP_POI `6e469a0` | WWCP_POI3 | `trust-role` | low-medium | 6 |
| [D6](#d6-foreign-operator) | ✅ A proof's certificates and key statement may name another roaming network operator: **fixed** in WWCP_POI `65e658d` | WWCP_POI3 | `trust-certificate-operator`, `trust-statement-operator` | low-medium | 19 |
| [D7](#d7-certificate-twice) | ✅ A certificate may name a hardware revision or firmware version twice, and so may the energy meters it was issued with: **fixed** in WWCP_POI.TS `b9c786e` | WWCP_POI.TS | `version-text-certificate-twice`, `version-text-certificate-energy-meter-twice` | low | - |

In D1 to D6 WWCP_POI.TS refused what the vector says is to be refused, and WWCP_POI3 took it; in D7 it was the other way
round. All seven are fixed: on all 288 vectors the two implementations agree (see
[What both do alike](#what-both-do-alike)).

Observations that are no deviation between the two, but worth knowing, follow at the end:
[O1](#o1-internal-reader) to [O4](#o4-no-valid-until).


<a id="d1-lenient-json"></a>
## D1. ✅ The JSON reader for hashing takes what is no JSON

**Vectors:** `refuse-trailing-comma-array`, `refuse-trailing-comma-object`, `refuse-comment`, `refuse-single-quotes`,
`refuse-unquoted-name`, `refuse-leading-zero`, `refuse-hex-number`, `refuse-raw-control-character`,
`refuse-second-value` (`poi-canonical-json.json`, `invalidInputs`).

**Where:** `WWCP_POI3/DataStructures/POIJSON.cs` (`Read`, `ReadFrom`): a Newtonsoft `JsonTextReader` with
`DateParseHandling.None`, `FloatParseHandling.Decimal` and `DuplicatePropertyNameHandling.Error`, and, when the
document holds decimals, a second pass over them with `System.Text.Json`. Both are right about what they check;
Newtonsoft is lenient about the rest.

What WWCP_POI3 reads, and how it hashes it:

| Input | Taken as | Canonical JSON |
|---|---|---|
| `[1,]`, `{"a":1,}` | `[1]`, `{"a":1}` | the same |
| `{"a":1/* a comment */}` | `{"a":1}` | `{"a":1}` |
| `{'a':1}`, `{a:1}` | `{"a":1}` | `{"a":1}` |
| `[01]` | `[1]` | `[1]` |
| `[0x10]` | `[16]` | `[16]` |
| `["a<TAB>b"]` (a raw tab) | `["a\tb"]` | `["a\tb"]` |
| `{"a":1} {"b":2}` | `{"a":1}`, the rest dropped | `{"a":1}` |

WWCP_POI.TS refuses all of them, as RFC 8259 does (Styx section 1: "A JSON document is a tree … (RFC 8259)").
`NaN`, `Infinity`, `+1`, `.5`, `1.`, `\x41`, unclosed documents and empty texts both refuse.

**Why it matters:** what a server takes, it hashes and signs as its canonical form, so the leniency does not break a
signature; it makes the two implementations disagree on what is a valid request. A change set, a commit or a price
statement posted to a C# server in one of these forms is taken there and refused by every TypeScript client and server
given the same bytes. `0x10` and `01` are the sharp edges: other readers take them as 16 and 1, as octal 8 and 1, or
refuse them. And `{"a":1} {"b":2}` drops what follows the first value **silently**: a body of two documents is taken as
its first.

**Fix:** let `POIJSON.Read` refuse what RFC 8259 refuses - e.g. read with `System.Text.Json`'s `Utf8JsonReader`
(strict by default, no comments, no trailing commas) and build the `JToken` from it, or check the whole text with it
first, as `CheckDecimals` already does for the decimals, and refuse anything but whitespace after the first value.

**Fixed** in WWCP_POI `2c90847`, as SPECIFICATION.md section 1 says now: `POIJSON.Read` checks every text, not
only one with decimals, with `System.Text.Json`'s `Utf8JsonReader` as RFC 8259 writes JSON - no comments, no trailing
commas, nothing but whitespace after the first value - in the same pass that checks the decimals, a stream of a store as
well. `ReadFrom`, for a WebSocket message, checks its first value and leaves what follows to its caller, which refuses
it. Both implementations refuse all nine vectors.


<a id="d2-proof-revision"></a>
## D2. ✅ A station proof may name another revision than its attestations

**Vector:** `stationProof-revision` (`poi-refusals.json`): the station proof of `DE*GEF*E1*1` of the frozen run with
its `revision` changed, its `commitId` not.

**Where:** `WWCP_POI3/Proofs/RoamingNetworkProof.cs`, `AttestationsOf`: an attestation counts when its
`roamingNetworkId`, `commitId`, hash algorithm and validity fit; its `revision` is not compared with the proof's.
WWCP_POI.TS compares `roamingNetworkId`, `commitId`, `revision` and the hash algorithm (`ChargingStationProof.verify`).

**Why it matters:** the commit identifies its revision, so no other version is taken. But the revision the proof names
is shown to whoever checks it (`RoamingNetworkProof.Revision`), and is not what anybody signed.

**Fix:** compare `attestation.Revision` with `Revision` where the proof names one, as with `CommitId`.

**Fixed** in WWCP_POI `2c90847`, as SPECIFICATION.md 8.4 says now: an attestation counts for a proof only where
it names the commit and the revision the proof names. Both implementations refuse `stationProof-revision`.


<a id="d3-future-attestation"></a>
## D3. ✅ An attestation counts before it was signed

**Vectors:** `stationProof-before-signed` (`poi-refusals.json`), the station proof of the frozen run checked one second
before its attestations were signed, its key statement and certificates already valid; `trust-future`
(`poi-trust.json`), the same with signatures of the keys of SPECIFICATION.md section 6.

**Where:** `WWCP_POI3/History/RoamingNetworkAttestation.cs`, `IsValidAt`: `!ValidUntil.HasValue || Timestamp <=
ValidUntil`, nothing about `signedAt`. WWCP_POI.TS: `signedAt <= at && (validUntil === undefined || at <= validUntil)`.

**Why it matters:** *csharp-review 7*, now shown with data: an offline verifier takes an attestation that claims a time
after the one it is checked at. Together with keys checked at the attestation's own `signedAt`, a back-dated or
forward-dated attestation is taken as now.

**Fix:** `IsValidAt` requires `SignedAt <= Timestamp` (SPECIFICATION.md 8.5 should say so; the vector names its basis
"proposed").

**Fixed** in WWCP_POI `be07037` (SPECIFICATION.md 8.5, Validity, and 8.6): an attestation is valid from its `signedAt`
to its `validUntil`, which it gives, at most 24 hours later, and its signing key counts when it is valid when it attested
and at the time the proof is checked. Both implementations refuse `stationProof-before-signed` and `trust-future`; the
new vectors `trust-a-day` (taken), `trust-too-long` and `trust-key-ended` (refused) hold both to the rest of
*csharp-review 7*, and `trust-no-valid-until` is refused by both ([O4](#o4-no-valid-until)).


<a id="d4-subject-attestation"></a>
## D4. ✅ An attestation of a subject counts for the whole proof

**Vector:** `trust-subject` (`poi-trust.json`): the quorum of `DE*RNO` is two holders; Alpha attests the root, Beta only
the digest of `DE*GEF` (`"subject": {"entityType": "ChargingStationOperator", "entityId": "DE*GEF", "digest": …}`).

**Where:** `WWCP_POI3/Proofs/RoamingNetworkProof.cs`, `AttestationsOf` and the quorum count of `Verify`: root and
subject attestations are counted together. WWCP_POI.TS counts root attestations only.

**Why it matters:** *csharp-review 6*, now shown with data. A subject attestation attests one entity; counted for the
proof, it vouches for everything the proof gives above that entity as well - the name of the network, its operator, the
manufacturers and models, the transparency software. With a quorum of one, a subject attestation alone verifies the
whole proof.

**Fix:** count a subject attestation for its subject only, never for the proof.

**Fixed** in WWCP_POI `6e469a0` (SPECIFICATION.md 8.4 and 8.5): only attestations of the root count for the proof;
`VerifySubject` verifies the operator a subject attestation names, as the proof gives it, and nothing above it. Both
implementations refuse `trust-subject`.


<a id="d5-attestation-role"></a>
## D5. ✅ The role of an attestation is not checked

**Vector:** `trust-role` (`poi-trust.json`): Beta attests the root with its certified signing key of `DE*RNO`, in the
role `witness`.

**Where:** `WWCP_POI3/Proofs/RoamingNetworkProof.cs`: `role` and `signer` of attestations are not checked. WWCP_POI.TS
counts attestations in the role `roamingNetworkOperator` only.

**Why it matters:** *csharp-review 6*. The role is signed, so nobody else can change it; but an attestation its signer
made as something else - a witness, a charging station operator attesting its own node - counts as one of the roaming
network operator.

**Fix:** count attestations in the role `roamingNetworkOperator` only.

**Fixed** in WWCP_POI `6e469a0` (SPECIFICATION.md 8.5): attestations of the root count for the proof in the role
`roamingNetworkOperator` only. Both implementations refuse `trust-role`.


<a id="d6-foreign-operator"></a>
## D6. ✅ A proof's certificates and key statement may name another roaming network operator

**Vectors:** `trust-certificate-operator` (the certificate of Beta's signing key names `DE*XYZ`) and
`trust-statement-operator` (the key statement names `DE*XYZ`), `poi-trust.json`.

**Where:** `WWCP_POI3/Proofs/RoamingNetworkProof.cs`, `Verify`: the `roamingNetworkOperatorId` of the certificates and
of the key statement is not compared with the operator the proof gives; the check of a full version
(`RoamingNetworkOperator`) does compare them. WWCP_POI.TS compares both in `ChargingStationProof.verify`.

**Why it matters:** *csharp-review 19*. The certificate is signed by a trusted identity key, so this needs a holder of
the quorum; but a statement or certificate that holder made for another operator, e.g. of another roaming network
sharing the holder, is taken as one of this operator.

**Fix:** refuse, in `Verify`, a key statement or certificate of another operator than the proof's.

**Fixed** in WWCP_POI `65e658d`, as SPECIFICATION.md 8.6 requires: `Verify` refuses a key statement of another operator
than the one the proof gives, in the words of WWCP_POI.TS, and counts no attestation by a signing key certified for
another one. Both implementations refuse `trust-certificate-operator` and `trust-statement-operator`.


<a id="d7-certificate-twice"></a>
## D7. ✅ A certificate may name a hardware revision or firmware version twice

**Vectors:** `version-text-certificate-twice` (the certificate `PTB-2026-0017` names the hardware revision `2.1`
twice) and `version-text-certificate-energy-meter-twice` (the energy meter `PTB-2026-0042` was issued with names it
twice), `poi-refusals.json`: the head of the frozen run so changed, without its `eTags`.

**Where:** WWCP_POI.TS `src/network/versionTexts.ts`, `invalidCertifiedVersion`: it refuses a hardware revision or
firmware version of a certificate, and of the energy meters it was issued with, that is no text, empty, or beginning or
ending with whitespace, but takes one given twice ("A certificate may name one twice"), and `tests/versionTexts.test.ts`
expects so. WWCP_POI3 takes them through `ModelVersions.Of`, as the versions of a model (`ConformityCertificate` and
`CertifiedEnergyMeter` of WWCP_POI2), and refuses one given twice: "A hardware revision of the certificate
'PTB-2026-0017' must not be given twice!". `docs/ConformityAssessmentBody.md` of WWCP_POI says "each once".

**Why it matters:** low. Both calculate the same, as the content keeps these arrays as given (SPECIFICATION.md
section 2); but WWCP_POI.TS takes a roaming network version that WWCP_POI refuses to read, and that no WWCP_POI server
holds.

**Fix:** refuse, in `invalidCertifiedVersion`, a hardware revision or firmware version given twice, in the words of
WWCP_POI, and turn the test round.

**Fixed** in WWCP_POI.TS `b9c786e`: `invalidCertificateVersion` refuses a hardware revision or firmware version a
certificate or an energy meter it was issued with names twice, in the words and in the order of WWCP_POI - the texts of
the certificate, each energy meter with its texts and then its versions twice, and last the certificate's versions twice
-, and so does `invalidModelVersion` for a model, once both its arrays were read. Both implementations refuse
`version-text-certificate-twice` and `version-text-certificate-energy-meter-twice`.


## What both do alike

Both implementations calculate, byte for byte, and take or refuse alike:

- canonical JSON and deterministic CBOR: 57 vectors of Styx (section 4, its escaping table code point by code point,
  unpaired surrogates), and the refusal of decimals a `System.Decimal` can not hold, of properties named twice and of
  what RFC 8259 does not call JSON (D1);
- Base64 as POI reads it (canonical only) and Base45 (RFC 9285);
- every example of SPECIFICATION.md section 6: content, ETags, skeletons and the effective tree, the identifications of
  the genesis of both epochs (SHA-256 and SHA-512), key thumbprints, the signatures, the digest of the price statement,
  the trust anchor and its QR code;
- of the frozen run of the C# examples: the ETags of 14 versions, the identifications of 51 commits and 8 checkpoints,
  6 commit proofs against their checkpoints, the digests and chains of 8 price statements, 2 trust anchors and their QR
  codes, 5 station proofs (root, and verified against the trust anchor of their epoch), and the **replay of the whole
  history of QA commit by commit**: every change set of both epochs applied with its owners' signatures checked, the
  checkpoints 0 to 6 of epoch 1, the genesis of epoch 2, epoch 2 up to the head;
- the refusal of 56 changed documents: commits, checkpoints, versions, commit proofs, station proofs, price statements
  and trust anchors; among them a station proof naming another revision than its attestations (D2), a change set
  naming `rebasedFrom` rightly with a change without `oldValue`, which a rebase may have overwritten a concurrent change
  with (csharp-review 12; WWCP_POI `1717ee2`, WWCP_POI.TS `4e4ec38`), and versions naming twice an identification
  unique within the roaming network - an EVSE
  group of a provider and an operator of the same prefix, an energy meter, a grid connection point, an energy meter
  template, a transparency software release and a certificate, compared without case - refused for it in the same words
  (WWCP_POI.TS since `e32c2cd`), and versions naming a serial number, hardware revision or firmware version WWCP_POI
  does not read - empty, or beginning or ending with whitespace as `Char.IsWhiteSpace` tells it, U+0085 as well - of a
  charging station, an energy meter, their templates, a model and a certificate, or a model, a certificate or an
  energy meter a certificate was issued with naming one twice (WWCP_POI.TS since `24c97a6`, D7);
- all 22 trust vectors: a valid proof, expired attestations, attestations of the future (D3), one holder only
  (also twice), a key that may not sign for the party, a signing key expired before it attested and one that ended
  after it attested, a key certified by another holder's identity key, an uncertified key, other identity keys pinned,
  the quorum of the key statement above the one of the trust anchor, an attestation of another network, a changed
  entity, a wrong signature, a subject attestation and one in the role of a witness counted for the quorum (D4, D5), a
  certificate and a key statement of another roaming network operator (D6), attestations without `validUntil`
  ([O4](#o4-no-valid-until)), valid for a day, and valid longer.


## Observations

<a id="o1-internal-reader"></a>
### O1. A C# client can not read JSON as POI requires

SPECIFICATION.md section 1: "Whoever reads JSON in order to hash it again MUST read numbers with a fraction as
decimals …, MUST be refused …; so MUST an object that names a property twice." WWCP_POI3 does so in `POIJSON.Read`,
which is `internal`. A C# client verifying documents itself - or this harness - has no public way to read them as POI
does: `RoamingNetworkCommit.TryParse(String)` and others call it, `RoamingNetwork.TryParse` has no `String` overload,
and the pattern of the C# examples (`examples/csharp/helpers.cs`, `ReadJSON`) lacks the duplicate and decimal checks.
The harness calls `POIJSON.Read` by reflection (`VectorFiles.cs`). Making it public, or giving `RoamingNetwork` a
`TryParse(String)`, would close this.

<a id="o2-etag-tryparse"></a>
### O2. `ETag.TryParse(String)` is less strict than `ETag.Parse(String)`

`WWCP_POI3/ChangeSet/ETag/ETag.cs`: `Parse` refuses non-canonical Base64 digests, `TryParse` (`:224`) does not check
the round trip. Read in the code, not shown by a vector: the text form of an ETag is C# API, no wire format both
implementations share.

<a id="o3-unchecked-history"></a>
### O3. A history without a verifier of signatures

`RoamingNetworkHistory.TryAppend` of WWCP_POI3 refuses a signed commit when it is given no verifier of commit
signatures ("is signed, but there is no verifier of commit signatures!"); `History` of WWCP_POI.TS appends it, its
signatures unchecked, when `HistoryOptions.verifyCommit` is left out (the same for checkpoints). Not a difference in
what either calculates - the replay vector checks content and says so (`commitAndCheckpointSignatures: "unchecked"`) -
but in what an API takes by default: WWCP_POI.TS could refuse signed commits without a verifier, as WWCP_POI3 does.

<a id="o4-no-valid-until"></a>
### O4. ✅ Attestations without `validUntil` are valid forever, in both

`trust-no-valid-until` (`poi-trust.json`, expected `accepted`): both implementations take attestations without
`validUntil` two weeks after they were signed. SPECIFICATION.md 8.5 lets `validUntil` out; *csharp-review 7* proposes
to require it. The vector pins the agreement: should one implementation start refusing them, it turns red, and the
specification has to decide first.

**Decided** in WWCP_POI `be07037`: SPECIFICATION.md 8.5 requires `validUntil`, at most 24 hours after `signedAt`. The
vector expects `refused` now, and both implementations refuse it when they read the attestations.


## Not covered by vectors yet

Of *csharp-review*: keys removed in a later version signing change sets for an older one (3), change sets committed by
their `@id` alone (4), witnesses signing checkpoints of a history started from a snapshot (5), `lastChange` of what
embeds a changed entity (8, where the TypeScript port does as the C# code, against the specification), the order of
arrays in change sets (10), `epoch` in checkpoints of epoch 1 (11, both write and read it), changes without `oldValue`
(12, but for a rebased change set, above; the rebase itself is a server's), the RNO signing in place of parties without
keys (13), and the algorithms of the first checkpoint of a later
epoch (14). Most need a history signed anew - a vector maker with
fixed keys on the C# side (Styx signs ECDSA after RFC 6979 and ML-DSA deterministically as well) - or server behavior,
which no verifier vector reaches.

Of the texts WWCP_POI reads as given since `c31e5e3` and `3672b06`: that it takes them so - whitespace inside, case, a
leading U+FEFF, which `Char.IsWhiteSpace` does not take for whitespace -, as `poi-refusals.json` holds refusals only;
and a change set leading to a text it refuses, which needs a history signed anew as well.

ECDSA twins of price statements (2) are fixed in WWCP_POI `dbf39b0`: the digest of a statement leaves its signature
value out. The frozen run holds the twin of a statement (`proofs/QA-priceStatement-malleated-twin.json`), and both
implementations calculate for it the digest of the genuine statement (`poi-history.json`, `priceStatements`).

The quorum counted by holders the counted keys name (1) is fixed in WWCP_POI `3e32f48`: a trust anchor names the keys
per holder, the holders are counted as the verifier knows them, and a key keeps its holder. The trust vectors hold it
for both implementations, signed by the generator with a second identity key of Alpha: `trust-holder-keys` (both keys
of Alpha one holder, taken), `trust-holder-renamed` (a key statement naming one of them as Beta's, refused) and
`trust-holder-unnamed-key` (a key the statement does not name certifying a signing key of "Beta", counted for Alpha,
refused).
