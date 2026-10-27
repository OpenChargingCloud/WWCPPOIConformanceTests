# Where WWCP_POI3 and WWCP_POI.TS differ

What running both implementations against the golden vectors of this repository found: where the C# implementation
(WWCP_POI3, `libs/WWCP_POI` at `8f66f2f`, Hermod `fbb442f`, Styx `06b592d3`) and the TypeScript port (WWCP_POI.TS,
`libs/WWCP_POI.TS` at `42671c4`) take or calculate different things.

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
| [D8](#d8-expired-signature) | ✅ A change set signed, besides by its owner, by a key of a party not valid at its `createdAt` is taken: **fixed** in WWCP_POI.TS `e2b66b6` | WWCP_POI.TS | `key-expired-besides` | low (interop) | 3 |
| [D9](#d9-certificate-malformed) | ✅ A certificate WWCP_POI3 refuses to read is taken: for no model or for two, a model without its manufacturer or a manufacturer without its model, no hardware revision or firmware version, also of an energy meter it was issued with, a relative `documentURL`, an empty legislation, a `notAfter` before its `notBefore`, no release, one twice or both verified and compatible, energy meters of an energy meter model, one model twice: **fixed** in WWCP_POI.TS `1f0d9c7` | WWCP_POI.TS | the 16 `version-certificate-*` | low | - |

In D1 to D6 WWCP_POI.TS refused what the vector says is to be refused, and WWCP_POI3 took it; in D7 it was the other way
round. D8, found by the histories the generator signs (`poi-histories.json`), was the other way round as well, and so
is D9, found by vectors of the certificates WWCP_POI3 refuses to read. All nine are fixed: of the 379 vectors both
implementations run 337 - the 7 requiring `signing` and the 13 of `poi-histories.json` that WWCP_POI.TS leaves to
WWCP_POI are WWCP_POI3's alone - and agree on every one of them (see [What both do alike](#what-both-do-alike)).

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


<a id="d8-expired-signature"></a>
## D8. ✅ A change set signed, besides by its owner, by a key not valid at its `createdAt` is taken

**Vector:** `key-expired-besides` (`poi-histories.json`): the EVSE `DE*GEF*E1*1` of `history-parties` changes, its
change set signed by the signing key of `DE*GEF` for infrastructure and, besides, by another one of `DE*GEF` for
infrastructure that expired half a minute before its `createdAt`. Its control, signed by the first key alone, is taken
by both; signed besides by a valid key of another party, it is taken by both as well (`signature-of-another-party`).

**Where:** WWCP_POI.TS, `src/history/apply.ts`, `checkOwnership`: every signature must verify, by a key of a party of
the version or by a new identity key of one of its changes; whether the key is valid at `createdAt` is asked only of the
keys counted for an owner (`signedValid`). Its comment says more: "every signature valid, by a key of a party of the
version valid at `createdAt` or by a new identity key of one of its changes". WWCP_POI3,
`WWCP_POI3/RoamingNetwork/RoamingNetwork.Ownership.cs`, `TryGetSigners`, does so: "Signature 1: the key '…' of the
ChargingStationOperator 'DE*GEF' is not valid at 2026-10-18T08:08:00.000Z!".

**Why it matters:** the extra signature gives nobody anything, the valid one of its owner decides. But the two take
different histories: a change set a C# server refuses, a TypeScript verifier replaying the history takes, and with
`notBefore` the same holds for a key not valid yet. SPECIFICATION.md says it of a change set waiting (4.2: "every
signature it has is valid by a key of that version valid at its `createdAt` and when it takes it, or by a new identity
key of one of its changes"); of every change set 4.1 says only "Every signature MUST be by a key of a party, or by a new
identity key": the vector names its basis "proposed" for a commit.

**Fix:** `checkOwnership` refuses a signature by a key of a party that is not valid at `createdAt`, as its comment says
and as WWCP_POI3 does; a new identity key proving its possession stays exempt, its `notBefore` may still be to come
(4.1). SPECIFICATION.md 4.1 could say it of every change set.

**Fixed** in WWCP_POI.TS `e2b66b6`: every signature by a key of a party of the version is by one valid at the
`createdAt` of the change set, also one besides the signatures of its owners, refused otherwise in the words of
WWCP_POI3 ("Signature 1: the key '…' of the ChargingStationOperator 'DE*GEF' is not valid at
2026-10-18T08:08:00.000Z!"); a new identity key may still be one valid later (`tests/ownership.test.ts`). Both
implementations refuse `key-expired-besides`, and `key-expired` in the same words, which both name as `reason` now.
SPECIFICATION.md 4.1 says it of a change set waiting only; the basis of the vector stays "proposed" for every one.


<a id="d9-certificate-malformed"></a>
## D9. ✅ A certificate WWCP_POI3 refuses to read is taken

**Vectors:** the 16 `version-certificate-*` (`poi-refusals.json`): the head of the frozen run, without its `eTags`,
with one of its two certificates changed - `PTB-2026-0017`, for the energy meter model `KDM-500` of `KERNBERG`, or
`PTB-2026-0042`, for the charging station model `GD-DC300` of `GraphDefined`, issued with `KDM-500`. WWCP_POI3 refuses
each in the words its `reason` names:

| Vector | The certificate | WWCP_POI3 |
|---|---|---|
| `version-certificate-model-none` | `PTB-2026-0017` names no model | "The certificate 'PTB-2026-0017' must be for either a charging station model or an energy meter model!" |
| `version-certificate-model-both` | `PTB-2026-0017` names `GD-DC300` of `GraphDefined` as well | the same |
| `version-certificate-model-without-manufacturer` | `PTB-2026-0042` names `GD-DC300` without its manufacturer | "… must name the charging station model it is for with its manufacturer!" |
| `version-certificate-manufacturer-without-model` | `PTB-2026-0017` names `KERNBERG` without its model | "… must name the energy meter model it is for with its manufacturer!" |
| `version-certificate-hardware-revisions-none` | `PTB-2026-0017` names `[]` | "… must name at least one hardware revision of its model!" |
| `version-certificate-firmware-versions-none` | `PTB-2026-0042` names none | "… must name at least one firmware version of its model!" |
| `version-certificate-document-url-relative` | `PTB-2026-0017` names `certificates/PTB-2026-0017.pdf` | "documentURL: expected an absolute URL." |
| `version-certificate-legislation-empty` | `PTB-2026-0042` names `" "` | "A legislation must not be empty." |
| `version-certificate-validity-reversed` | `PTB-2026-0017` ends a millisecond before it begins | "notBefore must not exceed notAfter." |
| `version-certificate-release-none` | `PTB-2026-0017` names no release | "A document must identify at least one software release." |
| `version-certificate-release-twice` | `PTB-2026-0042` names `chargy-1.5.0` verified twice | "Empty or duplicate TransparencySoftware reference." |
| `version-certificate-release-both` | `PTB-2026-0042` names it compatible as well, as `CHARGY-1.5.0` | "A release cannot be both verified and merely compatible in the same document." |
| `version-certificate-energy-meters-of-meter-model` | `PTB-2026-0017`, of an energy meter model, names `KDM-500` as an energy meter it was issued with | "The certificate 'PTB-2026-0017' of an energy meter model names no energy meters!" |
| `version-certificate-energy-meter-twice` | `PTB-2026-0042` names `KDM-500` again, as `kdm-500` | "The energy meter model 'KDM-500' of 'KERNBERG' must not be given twice in the certificate 'PTB-2026-0042'!" |
| `version-certificate-energy-meter-hardware-revisions-none` | its energy meter names `[]` | "The certified energy meter model 'KDM-500' of 'KERNBERG' must name at least one hardware revision!" |
| `version-certificate-energy-meter-firmware-versions-none` | its energy meter names none | "… must name at least one firmware version!" |

**Where:** WWCP_POI3 reads a certificate through `ConformityCertificate` and `CertifiedEnergyMeter` of WWCP_POI2:
`StrictJSON.Link` refuses a `documentURL` that is not absolute, the constructors refuse the rest. WWCP_POI.TS reads of a
certificate its identification (unique in the roaming network), who states it (`src/history/apply.ts`) and the texts of
its versions (`src/network/versionTexts.ts`, D7), nothing else of its shape: it takes all 16. `docs/ConformityAssessmentBody.md`
of WWCP_POI says each rule, and the generator quotes it: "For exactly one model …, each with its manufacturer",
"Mandatory, at least one", "Absolute", "not before `notBefore`", "At least one release in both lists together; a release
not in both, not twice, not empty", "each model once", "A certificate for an energy meter model names none".

**Why it matters:** low. A certificate enters a version only by a change set its body, or the roaming network operator
in its place, signs, and no WWCP_POI server holds one of these; but WWCP_POI.TS takes a roaming network version that
WWCP_POI refuses to read, and a station proof gives its verifier the certificates as they are.

**Fix:** refuse them where `RoamingNetwork.parse` refuses the texts of D7, in the words of WWCP_POI3 and in its order:
first what it reads as the arguments of a certificate - the texts of its versions, each energy meter it was issued with
(its texts, its versions twice, at least one of each), its `documentURL` - then what the constructor checks: the model,
the versions twice, at least one of each, the legislation, the validity, the releases, the energy meters.

**Fixed** in WWCP_POI.TS `1f0d9c7`: `src/network/certificates.ts`, `invalidCertificates`, which
`RoamingNetwork.parse` checks after `invalidVersionText`, also for the version a change set leads to, reads a certificate
as `ConformityCertificate.TryParse` does, in its words and in its order: first its arguments, by their path after the
certificate - the JSON types of its model, the texts of its versions (moved there from `versionTexts.ts`, in the same
words), its releases (not empty once trimmed), each energy meter it was issued with (an object, of a manufacturer and a
model, its texts, its versions twice, at least one of each), the types of its document number and URL, an absolute
`documentURL`, timestamps with an explicit offset, the type of its legislation -, then what the constructor checks: the
model, the versions twice, at least one of each, the legislation, `notBefore` not after `notAfter` to the tick, the
releases each once (ordinally, once trimmed, as `References` compares them), at least one, none both verified and
compatible (without case), the energy meters of a charging station model only, each model once - of those named twice
the one named first, as `GroupBy` gives it. `tests/certificates.test.ts` holds it, and the order. Both implementations
refuse all 16 `version-certificate-*`, in the words their `reason` names.

**Not covered:** WWCP_POI3 reads a certificate strictly, as every entity (`StrictJSON`): an unknown property, a
property of another JSON type, a timestamp without its offset is an error; WWCP_POI.TS takes them, of every entity but
the properties of a certificate it reads since D9 - an unknown property also there. No vector holds it yet, as it is
not of certificates alone. And WWCP_POI3 compares the releases of a certificate for being
named twice ordinally (`References`), though without case for being both verified and compatible
(`TransparencySoftware_Id`), as releases are compared: by its code, `chargy-1.5.0` and `CHARGY-1.5.0` both verified are
taken, against "not twice", and WWCP_POI.TS takes them as well, as WWCP_POI3 does. A refusal vector can not say it
while both take it.


## What both do alike

Both implementations calculate, byte for byte, and take or refuse alike:

- canonical JSON and deterministic CBOR: 57 vectors of Styx (section 4, its escaping table code point by code point,
  unpaired surrogates), and the refusal of decimals a `System.Decimal` can not hold, of properties named twice and of
  what RFC 8259 does not call JSON (D1);
- Base64 as POI reads it (canonical only) and Base45 (RFC 9285);
- every example of SPECIFICATION.md section 6: content, ETags, skeletons and the effective tree, the identifications of
  the genesis of both epochs (SHA-256 and SHA-512), key thumbprints, the signatures, the digest of the price statement,
  the trust anchor and its QR code;
- custom data held as given (section 2; *csharp-review 20, 21*), in the content of the example of section 6, its
  canonical JSON and its ETags: decimals keeping their decimal places and digits a double does not hold, integers beyond
  53 and 64 bits and beyond the mantissa of a decimal, texts that look like timestamps in UTC, with an offset and
  without one, a JSON-LD context, objects and arrays nesting them, and the custom data of an address
  (`spec-2-custom-data-*`). WWCP_POI3 does since Styx `06b592d3`: against Styx `91901a9` it wrote
  `0.1000000000000000055511151231` as `0.1`, `1.50` as `1.5`, an integer of 39 digits as `1.2345678901234568E+38`,
  `"2026-10-26T07:00:00-05:00"` as `"2026-10-26T13:00:00.0000000+01:00"` in the time zone of the machine, dropped the
  custom data of the address, and its CBOR of a text that looks like a timestamp ended in an `InvalidCastException`;
- of the frozen run of the C# examples: the ETags of 14 versions, the identifications of 51 commits and 8 checkpoints,
  6 commit proofs against their checkpoints, the digests and chains of 8 price statements, 2 trust anchors and their QR
  codes, 5 station proofs (root, and verified against the trust anchor of their epoch), and the **replay of the whole
  history of QA commit by commit**: every change set of both epochs applied with its owners' signatures checked, the
  checkpoints 0 to 6 of epoch 1, the genesis of epoch 2, epoch 2 up to the head;
- the refusal of 72 changed documents: commits, checkpoints, versions, commit proofs, station proofs, price statements
  and trust anchors; among them a station proof naming another revision than its attestations (D2), a change set
  naming `rebasedFrom` rightly with a change without `oldValue`, which a rebase may have overwritten a concurrent change
  with (csharp-review 12; WWCP_POI `1717ee2`, WWCP_POI.TS `4e4ec38`), and versions naming twice an identification
  unique within the roaming network - an EVSE
  group of a provider and an operator of the same prefix, an energy meter, a grid connection point, an energy meter
  template, a transparency software release and a certificate, compared without case - refused for it in the same words
  (WWCP_POI.TS since `e32c2cd`), and versions naming a serial number, hardware revision or firmware version WWCP_POI
  does not read - empty, or beginning or ending with whitespace as `Char.IsWhiteSpace` tells it, U+0085 as well - of a
  charging station, an energy meter, their templates, a model and a certificate, or a model, a certificate or an
  energy meter a certificate was issued with naming one twice (WWCP_POI.TS since `24c97a6`, D7), and versions naming a
  certificate WWCP_POI does not read - for no model or for two, a model without its manufacturer and the other way
  round, without a hardware revision, a firmware version or a release, also an energy meter it was issued with without
  one of its versions, a relative `documentURL`, an empty legislation, ending before it begins, a release twice or both
  verified and compatible, compared without case, energy meters of an energy meter model, one model twice, compared
  without case (WWCP_POI.TS since `1f0d9c7`, D9);
- all 25 trust vectors: a valid proof, expired attestations, attestations of the future (D3), one holder only
  (also twice), a key that may not sign for the party, a signing key expired before it attested and one that ended
  after it attested, a key certified by another holder's identity key, an uncertified key, other identity keys pinned,
  the quorum of the key statement above the one of the trust anchor, an attestation of another network, a changed
  entity, a wrong signature, a subject attestation and one in the role of a witness counted for the quorum (D4, D5), a
  certificate and a key statement of another roaming network operator (D6), attestations without `validUntil`
  ([O4](#o4-no-valid-until)), valid for a day, and valid longer; and the holders of a quorum as the trust anchor names
  them (csharp-review 1), two identity keys of Alpha one holder, a key statement naming one of them as Beta's, and a key
  the statement does not name counted for the holder the trust anchor names;
- all 31 replays of `poi-histories.json` both run: histories the generator made and signed
  with keys whose seeds it gives (the Ed25519 keys of section 6, and Ed25519, Ed448 and ES256 keys of its own), every
  refusal with its control, the document refused but for what it is about, taken in its place: who signs in place of a
  party without keys and with which usages (csharp-review 13), who states a certificate (15), lastChange of what embeds
  a changed EVSE (8), old values, also `150000.0` for `150000`, and rebases with and without them (12), a signing key
  expired before the `createdAt`, also besides a valid one of its owner (D8), and one removed in the version before (3,
  in a linear history), new values with a
  JSON-LD context, out of their order or with a timestamp not to the millisecond (10), a withdrawal together with what
  names it (18), certificates of models in hardware revisions and firmware versions, of stations and of meters (16, 17),
  and three epochs, the first checkpoint of the third one signed with an algorithm of the second one only, and with one
  of neither (14); where both word a refusal alike, `reason` names it. The other 10, which WWCP_POI.TS leaves to
  WWCP_POI (the references a version holds, changes of a group of an e-mobility provider and of a grid connection
  point), hold WWCP_POI3 alone to them: a station in a firmware version its model does not have, of a hardware revision
  its certificate does not cover, a certificate of the other kind named by a station or a meter, a meter its station's
  certificate was not issued with (16, 17), a manufacturer or a model withdrawn while a station names it (18), a
  provider renaming, after it removed its group, the operator's group of the same identification (9), and a grid
  connection point the roaming network operator adds in place of a grid operator without keys (13).


## Observations

<a id="o1-internal-reader"></a>
### O1. ✅ A C# client can not read JSON as POI requires

SPECIFICATION.md section 1: "Whoever reads JSON in order to hash it again MUST read numbers with a fraction as
decimals …, MUST be refused …; so MUST an object that names a property twice." WWCP_POI3 does so in `POIJSON.Read`,
which is `internal`. A C# client verifying documents itself - or this harness - has no public way to read them as POI
does: `RoamingNetworkCommit.TryParse(String)` and others call it, `RoamingNetwork.TryParse` has no `String` overload,
and the pattern of the C# examples (`examples/csharp/helpers.cs`, `ReadJSON`) lacks the duplicate and decimal checks.
The harness calls `POIJSON.Read` by reflection (`VectorFiles.cs`). Making it public, or giving `RoamingNetwork` a
`TryParse(String)`, would close this.

**Closed** in WWCP_POI `33df473`, both: `POIJSON` is public with its reading alone - `Read(String, Int32)`,
`Read(Stream, Int32)`, `Reader` and `ReadFrom` - and `RoamingNetwork` has `Parse(String)` and `TryParse(String)`, read
with it, as the key statement, the signing key certificate, the withdrawal of a change set and the proofs of a commit
and of a price statement have; the examples read their files with it (`Helpers.ReadJSON`, `ReadJSONArray`). The
harness calls `POIJSON.Read` directly.

<a id="o2-etag-tryparse"></a>
### O2. `ETag.TryParse(String)` is less strict than `ETag.Parse(String)`

`WWCP_POI3/ChangeSet/ETag/ETag.cs`: `Parse` refuses non-canonical Base64 digests, `TryParse` (`:224`) does not check
the round trip. Read in the code, not shown by a vector: the text form of an ETag is C# API, no wire format both
implementations share.

<a id="o3-unchecked-history"></a>
### O3. ✅ A history without a verifier of signatures

`RoamingNetworkHistory.TryAppend` of WWCP_POI3 refuses a signed commit when it is given no verifier of commit
signatures ("is signed, but there is no verifier of commit signatures!"); `History` of WWCP_POI.TS appends it, its
signatures unchecked, when `HistoryOptions.verifyCommit` is left out (the same for checkpoints). Not a difference in
what either calculates - the replay vector checks content and says so (`commitAndCheckpointSignatures: "unchecked"`) -
but in what an API takes by default: WWCP_POI.TS could refuse signed commits without a verifier, as WWCP_POI3 does.

**Closed** in WWCP_POI.TS `161692b`: a signed commit or checkpoint without `verifyCommit` / `verifyCheckpoint` is
refused, also the commit of a snapshot, in the words of WWCP_POI3 ("The commit '…' is signed, but there is no verifier
of commit signatures!", the same for checkpoints). A snapshot is taken only anchored in a trust anchor, or unanchored
when asked for explicitly (`unanchored`). The replays, `commitAndCheckpointSignatures: "unchecked"`, pass verifiers
taking every signature and start unanchored, as they always checked content alone.

<a id="o4-no-valid-until"></a>
### O4. ✅ Attestations without `validUntil` are valid forever, in both

`trust-no-valid-until` (`poi-trust.json`, expected `accepted`): both implementations take attestations without
`validUntil` two weeks after they were signed. SPECIFICATION.md 8.5 lets `validUntil` out; *csharp-review 7* proposes
to require it. The vector pins the agreement: should one implementation start refusing them, it turns red, and the
specification has to decide first.

**Decided** in WWCP_POI `be07037`: SPECIFICATION.md 8.5 requires `validUntil`, at most 24 hours after `signedAt`. The
vector expects `refused` now, and both implementations refuse it when they read the attestations.


## The findings of csharp-review and their vectors

What of the 22 findings of *csharp-review* a verifier reaches, and which vectors hold the implementations to it. All but
one question of design in 19 are fixed in WWCP_POI; what is a server's (a witness, its journal, the clock taking a
change set, change sets waiting, rebasing and merging) no verifier vector reaches. Most findings needed a history
signed anew, which the keys of the frozen run, random and private, do not allow: `poi-histories.json` holds small
histories the generator signs itself (the replays named below are of it), every refusal with its control. Where a
vector says *WWCP_POI3 alone*, WWCP_POI.TS leaves what it checks to WWCP_POI (`notApplicable`), as its review says.

| # | Finding | Vectors | Not covered, and why |
|---|---|---|---|
| 1 | The holders counted for a quorum | `trust-holder-keys`, `trust-holder-renamed`, `trust-holder-unnamed-key` (`poi-trust.json`) | |
| 2 | ECDSA twins of price statements | `priceStatement:proofs/QA-priceStatement-malleated-twin.json#` (`poi-history.json`): the twin of a statement of the run has the digest of the genuine one | |
| 3 | A removed or expired key still signs, through an older version | `key-expired`, `key-removed`, in a linear history; `key-expired-besides` ([D8](#d8-expired-signature)) | Through an older version: a change set of a branch signed by a key the other tip removed, or let expire, conflicts in the merge (5.3). WWCP_POI.TS takes no merges, so a vector would hold WWCP_POI3 alone, and the generator would have to calculate the three-way merge of section 5.3. The clock of the server taking a change set (4.1) is a server's. |
| 4 | A change set counts as committed by its `@id` alone | `changeSet-id`, `changeSet-rebasedFrom`, `changeSet-without-changes`, `changeSet-merge-id` (`poi-refusals.json`) | `alreadyCommitted` and the change sets waiting (4.2) are a server's. |
| 5 | A witness signs the first checkpoint of a history started from a snapshot | | A witness and its journal are a server's. |
| 6 | A subject attestation verifies a whole proof | `trust-subject`, `trust-role` ([D4](#d4-subject-attestation), [D5](#d5-attestation-role)) | |
| 7 | Attestations without `validUntil`, keys checked at a self-chosen `signedAt` | `stationProof-before-signed`, `trust-future` ([D3](#d3-future-attestation)), `trust-no-valid-until`, `trust-a-day`, `trust-too-long`, `trust-key-ended` | |
| 8 | `lastChange` of what embeds a changed entity | `lastChange-and-old-value`, `lastChange-of-what-embeds-it` (as section 4 said before WWCP_POI `8e6a1fa`, refused); the replay of the run, `replay-QA-both-epochs` | |
| 9 | A provider's change of an operator's group, by a stale owner record | `owner-of-what-was-removed` (WWCP_POI3 alone: WWCP_POI.TS applies no change of a provider's group) | Energy meter templates and groups: there a stale record reaches only changes that applying refuses, in both, so no vector tells the owner rule from it. A grid connection point handed on within a change set: WWCP_POI.TS applies none. |
| 10 | What a signed change set says is not what the content holds | `new-value-context`, `new-value-keys-out-of-order`, `new-value-timestamp`; the replay of the run takes the values of its change sets as the content holds them | The written forms WWCP_POI.TS can not tell without the types of the values (an identification in another case, a country, a URL without its scheme, …) end in other afterETags there: refused as well, but for that. |
| 11 | Epoch 1 checkpoints name their epoch | `checkpoint-epoch` (`poi-refusals.json`); every checkpoint of the run and of `history-epochs` | |
| 12 | A change without `oldValue` is not checked at all | `old-value-other`, `old-value-decimal` (`150000.0` for `150000`), `old-value-none`, `rebased-with-old-values`, `rebased-without-old-value`, `rebased-add`; `changeSet-rebased-without-old-value` (`poi-refusals.json`) | The rebase itself (`TryRebase`) is a server's. |
| 13 | The RNO can not sign in place of a body or grid operator without keys | `rno-states-certificate`, `rno-states-certificate-with-keys-for-certificates`, `rno-states-certificate-with-keys-for-tariffs`, `rno-states-certificate-one-holder`; `rno-adds-grid-connection-point`, `rno-adds-grid-connection-point-with-keys-for-tariffs` (WWCP_POI3 alone: WWCP_POI.TS applies no change of a grid connection point) | The models of a manufacturer without keys a version names from before: a manufacturer is added with keys now. |
| 14 | The first checkpoint of a later epoch takes signatures of any algorithm | `epoch-first-checkpoint-algorithms-of-either`, `epoch-first-checkpoint-algorithm-of-neither`, `epoch-later-checkpoint-algorithm-of-before`, `epochs` | A snapshot of the third epoch naming the profiles of the second (`previousProfiles`): the replays start their epochs themselves. |
| 15 | Who stated a certificate can not be told once its body has keys | `rno-states-certificate-unsaid`, `body-certificate-said-by-rno`, `body-changes-certificate-said-by-rno`, `body-states-certificate-itself` | What a verifier tells of a station proof, the `statedBy` of its certificates: the vectors check what a proof is, not what an app shows of it. |
| 16 | A certificate is for a version of a model, but no station or meter names one | `parties-models-and-certificates`, `parties-station-and-meter`; `station-firmware-of-no-model`, `station-revision-not-certified` (WWCP_POI3 alone: WWCP_POI.TS leaves the references a version holds to WWCP_POI) | Templates naming them: the generator calculates no effective content of templates. |
| 17 | An energy meter names the certificate of a station model, and has none of its own | `parties-station-and-meter`; `station-certificate-of-a-meter`, `meter-certificate-of-a-station`, `meter-not-of-the-certificate` (WWCP_POI3 alone) | |
| 18 | What one party names blocks what another party withdraws | `withdrawn-with-what-names-it`; `withdrawn-while-named-party`, `withdrawn-while-named-model` (WWCP_POI3 alone) | |
| 19 | Smaller points | The quorum of a trust anchor by holders (see 1); certificates and a key statement of another operator, `trust-certificate-operator`, `trust-statement-operator` ([D6](#d6-foreign-operator)); a conformity assessment body and a grid operator added without keys, `parties-added`; what a model rates, `evse-above-its-model`, `model-below-what-names-it`, `meter-signing-not-as-its-model` (WWCP_POI3 alone) | The roles of checkpoint signatures and the key statements the examples trust are the verifier's and the examples'; which price statements an epoch takes along, decided in WWCP_POI `1964903`, is a server's; the other data of a model, which describe it and are compared with nothing, no vector reaches, nor a station above its model by a template; building the examples and the dependencies of COSE.TS no vector reaches. |
| 20 | Custom data: numbers as binary floating-point numbers, timestamps in the time zone of the server | `spec-2-custom-data-decimals`, `-integers`, `-texts`, `-nested` (`poi-specification.json`) | |
| 21 | The custom data of an address is lost | `spec-2-custom-data-address` (`poi-specification.json`) | |
| 22 | A peer starting from a snapshot passes over attestations it can not read | `anchored-head-unreadable-attestation`, `anchored-head-attestation-not-an-object` (`poi-histories.json`), against `TryFromAnchoredSnapshot`, which the peer uses | The peer itself, its connection and what it asks for |

No finding of the review, and not covered either: of the texts WWCP_POI reads as given since `c31e5e3` and `3672b06`,
that it takes them so - whitespace inside, case, a leading U+FEFF, which `Char.IsWhiteSpace` does not take for
whitespace -, as `poi-refusals.json` holds refusals only; and a change set leading to a text it refuses, which a
history of `poi-histories.json` could hold.
