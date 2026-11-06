# Where WWCP_POI3 and WWCP_POI.TS differ

What running both implementations against the golden vectors of this repository found: where the C# implementation
(WWCP_POI3, `libs/WWCP_POI` at `399b7c8`, Hermod `c15cadfe`, Styx `7642de3d`) and the TypeScript port (WWCP_POI.TS,
`libs/WWCP_POI.TS` at `cb53bd4`) take or calculate different things.

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
| [D10](#d10-text-of-no-language) | ✅ A text of a QI-Digital document in no language, or one that is no text, is left out while reading: the signature verifies, the text travels with the document unsigned: **fixed** in WWCP_POI `bbe8fb8` | WWCP_POI3 | `qid-calibration-text-of-no-language`, `qid-calibration-text-not-a-text` | low | new |
| [D11](#d11-station-serial-number) | ✅ The calibration certificate of a charging station is compared with its own serial number: taken for a station of another serial number, or of none: **fixed** in WWCP_POI.TS `9153bc6` | WWCP_POI.TS | `qid-calibration-station-replaced`, `qid-calibration-station-without-serial-number` | low | 23 |
| [D12](#d12-party-key-usage) | ✅ A version whose charging station operator names a signing key of a usage POI does not know is taken: the keys of a party are read where they are used, not with the version: **fixed** in WWCP_POI.TS `37b34f2` | WWCP_POI.TS | `version-key-usage-unknown` | low | new |
| [D13](#d13-written-forms) | ✅ A key written otherwise than POI writes it is taken and written again: a `notAfter` with an offset, of a date only or `null`, a COSE key in CBOR that is not deterministic - with an offset and in CBOR that is not deterministic against the `eTags` of the version as published: **fixed** in WWCP_POI `a425530` | WWCP_POI3 | `version-key-not-after-offset`, `version-key-not-after-date`, `version-key-not-after-null`, `version-key-cbor-not-deterministic` | medium (interop) | new |
| [D14](#d14-body-malformed) | ✅ A conformity assessment body WWCP_POI3 refuses to read is taken: a certificate under a legislation it is not notified for, a `notifiedBodyNumber` not of four digits, a `notifiedFor` empty or given twice: **fixed** in WWCP_POI.TS `4ff1fc2` | WWCP_POI.TS | `version-body-certificate-not-notified`, `version-body-number-three-digits`, `version-body-notified-for-empty`, `version-body-notified-for-twice` | low | - |
| [D15](#d15-content-as-held) | ✅ A version written otherwise than the content holds it is taken, and written again: what the content orders out of its order, the texts of an ordered list untrimmed, a list given empty, a property given as `null`, an embedded object naming its JSON-LD context, a text in languages keyed otherwise, a timestamp with an offset, a property of a key or of an EV Taler merchant POI does not read, a URL without its scheme - 10 of them against the `eTags` of the version as published: **fixed** in WWCP_POI `3de830a` and `1de4dff` | WWCP_POI3 | the 27 `version-held-*` | medium (interop) | new |
| [D16](#d16-tariff-id) | ✅ A price statement naming a charging tariff not as `{operatorId}*T{suffix}` is taken, which WWCP_POI3 refuses as it reads it: its signature counts as valid, the price only does not apply: **fixed** in WWCP_POI.TS `80afec7` | WWCP_POI.TS | `sessionPrice-foreign-tariff` | low | new |
| [D17](#d17-time-zones) | ✅ A charging pool or charging pool template naming a time zone that is none of a region of the IANA time zone database as it writes it, or one the platform does not know, is taken: in the time zone `Intl` or its table of Windows names finds, else in UTC: **fixed** in WWCP_POI.TS `9cc620a` | WWCP_POI.TS | the 10 `version-time-zone-*` | medium (interop) | new |
| [D18](#d18-restrictions) | ✅ A version whose restrictions of a tariff element name a property their type does not define (`maxStateOfCharge`) is taken: WWCP_POI.TS compared the properties of an element and of its price components with those it writes, not of its restrictions: **fixed** in WWCP_POI.TS `ce88620` | WWCP_POI.TS | `version-held-restriction-unknown` | medium (interop) | new |

In D1 to D6 WWCP_POI.TS refused what the vector says is to be refused, and WWCP_POI3 took it; in D7 it was the other way
round. D8, found by the histories the generator signs (`poi-histories.json`), was the other way round as well, and so
is D9, found by vectors of the certificates WWCP_POI3 refuses to read. All nine are fixed. D10, found by the vectors of
the QI-Digital documents of example A14 (`poi-qidigital.json`), was WWCP_POI3's again, and is fixed as well. D11 is
*csharp-review 23*, which WWCP_POI.TS shared: fixed in WWCP_POI in the same commit as D10, and in WWCP_POI.TS
`9153bc6`. D12, found by the vectors of EV Taler (WWCP_POI `ec3dace`, WWCP_POI.TS `0aaf713`), was WWCP_POI.TS's, and
is fixed in WWCP_POI.TS `37b34f2`. D13, a key written otherwise than POI writes it, which WWCP_POI3 took and wrote
again, was WWCP_POI3's, and is fixed in WWCP_POI `a425530`. D14, a conformity assessment body WWCP_POI3 refuses to
read, was WWCP_POI.TS's, and is fixed in WWCP_POI.TS `4ff1fc2`. D15, a version written otherwise than the content holds
it, which WWCP_POI3 took and wrote again, was WWCP_POI3's, and is fixed in WWCP_POI `3de830a` and `1de4dff`. D16,
found by the vectors of the verifier extensions (`poi-verifier.json`), was WWCP_POI.TS's: a price statement naming a
charging tariff not as `{operatorId}*T{suffix}`, which SPECIFICATION.md says since WWCP_POI `89c5fa3`; it is fixed in
WWCP_POI.TS `80afec7`. D17, the time zones of charging pools, was WWCP_POI.TS's, since SPECIFICATION.md names them
(WWCP_POI `d1c41ca`, deciding [O5](#o5-time-zones)), and is fixed in WWCP_POI.TS `9cc620a`. D18, found by probing the
elements of a price status, was WWCP_POI.TS's: restrictions of a tariff element naming a property their type does not
define, which SPECIFICATION.md 2 refuses; it is fixed in WWCP_POI.TS `ce88620`, with the elements of a price status
written as a charging tariff holds them, which SPECIFICATION.md 12.1 says since WWCP_POI `5a72313`
([D16](#d16-tariff-id), "Since WWCP_POI `5a72313`"). Both implementations run every one of the 793 vectors - WWCP_POI3
alone signs the 7 signatures of section 6 again from their private seeds, which WWCP_POI.TS verifies only - and agree on
every one of them (see [What both do alike](#what-both-do-alike)). Among them are the 13 replays of `poi-histories.json`
WWCP_POI.TS left to WWCP_POI before: the references a version holds, which it checks since `813e1d7`, and the changes of
a group of an e-mobility provider and of a grid connection point, which it applies since `1946013`.

Observations that are no deviation between the two, but worth knowing, follow at the end:
[O1](#o1-internal-reader) to [O5](#o5-time-zones).


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



<a id="d10-text-of-no-language"></a>
## D10. ✅ A text of a QI-Digital document in no language, or one that is no text, is left out while reading

**Vectors:** `qid-calibration-text-of-no-language` and `qid-calibration-text-not-a-text` (`poi-qidigital.json`): the
calibration certificate `DCC-2026-0815` of `EM-LAB` as example A14 published it, the name of its measurement given in
`"xx"` as well, no language, or with the number 5 as its text in `"de"`. WWCP_POI.TS refuses each ("'xx' is no
language!", "the text in 'de' must be a text!"); WWCP_POI3 takes both, and verifies the signature.

**Where:** WWCP_POI3 reads the texts of a QI-Digital document with `POIJSON.TryParseI18N`, that is with
`ImmutableI18NString.TryParse` of Styx, which leaves out without a word a key that is no language of `Languages` and a
value that is no string. A QI-Digital document is signed as WWCP_POI3 writes it again from what it read
(`AQIDigitalDocument`: its context, its content and its signature without its value), so what it left out is no part of
what the signature covers: the text in `"xx"` verifies, and travels with the signed certificate, unsigned - what
`QIDigitalJSON.TryOnly` refuses an unknown property for. WWCP_POI.TS refuses both while reading
(`src/qidigital/json.ts`, `i18nOf`), and takes a language written in upper case, `EN`, as `en`. WWCP_POI.TS
found it reading the C# code; the vectors show it. Names of WWCP_POI3 are read strictly, both refuse a performance
location written `customer` or `1` alike (`POIJSON.TryParseEnum`: no case ignored, the name as it is written).

**Why it matters:** low. A reader of WWCP_POI3 shows nothing of the text it left out; a reader that shows the document
as it was handed out shows a text nobody signed, beside a valid signature.

**Fix:** refuse a key that is no language and a value that is no string where WWCP_POI3 reads the texts of a QI-Digital
document, in the words of WWCP_POI.TS: "'xx' is no language!", "the text in 'de' must be a text!".

**Fixed** in WWCP_POI `bbe8fb8`: `QIDigitalJSON.TryParseI18N` reads the texts of every QI-Digital document and part,
and the conditions of a certificate of conformity, refusing a key that is no language - also `1`, a language by its
number, which `Enum.TryParse` takes -, a value that is no text and a language given twice, in the words of WWCP_POI.TS;
`EN` is still `en`. Both refuse both vectors for what they are about.

**Not covered:** the texts of the entities of a roaming network are read by `POIJSON.TryParseI18N` as before; whether a
text left out there passes the ETags of a version, no vector shows yet.


<a id="d11-station-serial-number"></a>
## D11. ✅ The calibration certificate of a charging station is compared with its own serial number

**Vectors:** `qid-calibration-station-replaced` and `qid-calibration-station-without-serial-number`
(`poi-qidigital.json`): a calibration certificate of the charging station `DE*GEF*S2` - the certificate of the meter of
the run, for the station instead: its manufacturer, model, hardware revision and firmware version those of its template
`DE*GEF*ST_AC`, its serial number `GD-AC44-2026-0002` -, signed by the generator with an Ed25519 key of its own for
certificates, which QA patched gives EM-LAB besides its keys (the keys of the run are private). Checked against QA with
the station of the serial number `GD-AC44-2026-0003`, replaced since, and with the station of none. WWCP_POI3 refuses
both ("The charging station 'DE*GEF*S2' has the serial number 'GD-AC44-2026-0003', not 'GD-AC44-2026-0002'!", and
`''` for none); WWCP_POI.TS takes both. Their control, `qid-calibration-station`, the station of the certificate's
serial number, both take, and both refuse `qid-calibration-station-key-of-no-laboratory`, the certificate against QA
without the generator's key.

**Where:** `QIDigitalItem.verify` of WWCP_POI.TS (`src/qidigital/parts.ts`) builds the station of the roaming network as
`ofChargingStation(station, this.serialNumber)`, with the serial number of the certificate itself, as WWCP_POI3 did
before `bbe8fb8` (*csharp-review 23*): the two never differ. A charging station has a serial number of its own in the
roaming network, as its manufacturer marked it, and no template gives it.

**Why it matters:** low. A calibration certificate is one of a single instrument: taken for any station of the same
identification, model and versions, it still counts for a station replaced by another one.

**Fix:** take the serial number the roaming network gives the station, as `ofEnergyMeter` does the meter's
(`QIDigitalItem.Of(ChargingStation)` of WWCP_POI3 since `bbe8fb8`), in the same words; then remove D11 from
`DEVIATIONS` of the generator.

**Fixed** in WWCP_POI.TS `9153bc6`: `QIDigitalItem.ofChargingStation(station)` takes the serial number the roaming
network gives the station, and `verify` compares the certificate with it, in the words of WWCP_POI3. Both refuse both
vectors for what they are about.


<a id="d12-party-key-usage"></a>
## D12. ✅ A version whose charging station operator names a signing key of an unknown usage is taken

**Vectors:** `version-key-usage-unknown` (`poi-refusals.json`): the head of the frozen run, without its `eTags`, a
signing key of `DE*GEF` naming the usage `zzz` after `priceStatements` and `tariffs`. WWCP_POI3 refuses it ("Invalid
signing key '…': The usage 'zzz' of the public key '1cf5b42e…' is unknown: it is one of certificates, infrastructure,
models, party, payments, priceStatements, software, tariffs!"); WWCP_POI.TS takes it.

**Where:** WWCP_POI3 reads the keys of every party with the version they are part of (`POIPublicKey`, its usages
`POIKeyUsages`). `RoamingNetwork.parse` of WWCP_POI.TS (`src/network/roamingNetwork.ts`) reads the keys of the roaming
network operator only; those of a party it reads where it uses them - applying a change set (`src/history/apply.ts`),
verifying a price statement, a station proof or a QI-Digital document - with `POIPublicKey.parse` (`src/keys.ts`),
which refuses an unknown usage, in the words of WWCP_POI3. Found by the vectors of EV Taler (WWCP_POI `ec3dace`,
WWCP_POI.TS `0aaf713`), which adds the usage `payments`; it is older than EV Taler: WWCP_POI.TS `7e8949f` takes the
vector as well.

**Why it matters:** low. A key of an unknown usage signs nothing in either implementation, and WWCP_POI.TS refuses it
the first time it reads the keys of its party; but it takes a roaming network version that WWCP_POI refuses to read.

**Fix:** read the keys of every party where `RoamingNetwork.parse` reads the version, with `POIPublicKey.parseAll`, in
the words the vector's `reason` names; then remove D12 from `DEVIATIONS` of the generator.

**Fixed** in WWCP_POI.TS `37b34f2`: `RoamingNetwork.parse` reads the keys of every party, and the identity keys of the
roaming network operator, as WWCP_POI3 reads them wherever it reads a party (`invalidPartyKeys`,
`src/network/partyKeys.ts`; `POIPartyKeys.TryParse`, then `POIPartyKeys.Check`), in its order and its words: the
parties as `RoamingNetwork.TryParse` reads them, charging station operators last; every key as `POIPublicKey.parse`
reads it ("Invalid signing key '…': …"), then none twice, none both a signing and an identity key, no identity key
naming usages. `tests/partyKeys.test.ts` holds it. Both refuse `version-key-usage-unknown` for what it is about.

**Not covered:** a probe of WWCP_POI.TS with 47 variants of the keys of every party and of the roaming network
operator, against WWCP_POI3 `ec3dace`, found 40 alike in the same words, and besides, no vector holds yet:

- five keys both refuse, within the same frame in other words - without `@id` or `key`, a `key` that is no Base64,
  `notBefore` after `notAfter`, another `@context`: worded alike since WWCP_POI.TS `f13cdff`, which reads a key in the
  words and the order of `POIPublicKey.TryParse`;
- two keys WWCP_POI3 takes and WWCP_POI.TS refuses: a `notAfter` of a date only, or with an offset, now
  [D13](#d13-written-forms), with a timestamp `null` and a key in CBOR that is not deterministic;
- keys not in the order of their identifications, and an empty `signingKeys`, both take; WWCP_POI3 writes them sorted
  and without the empty array.


<a id="d13-written-forms"></a>
## D13. ✅ A key written otherwise than POI writes it is taken, and written again

**Vectors:** `version-key-not-after-offset`, `version-key-not-after-date`, `version-key-not-after-null` and
`version-key-cbor-not-deterministic` (`poi-refusals.json`): the head of the frozen run, the signing key `1cf5b42e…` of
`DE*GEF` for price statements and tariffs written otherwise - its `notAfter`, `2027-10-27T17:20:49.271Z`, as the same
instant with the offset `+02:00`, as the date `2027-10-27` or as `null`; its COSE key with the label 1 (kty) in two
bytes, `0x18 0x01`: the same key, in CBOR that is not deterministic. The first and the last keep the `eTags` of the
version as published, the other two, another content, leave them out. WWCP_POI.TS refuses all four ("The notAfter of
the key '…' must be written as yyyy-MM-ddTHH:mm:ss.fffZ, not '…'!", "… must be a text!", "Invalid COSE key: Invalid
deterministic CBOR: …"); WWCP_POI3 takes all four - the first and the last with the `eTags` as published.

**Where:** WWCP_POI3 reads a key (`POIPublicKey.TryParse`) as a value - a timestamp of any form it parses, `null` as
none, a COSE key in any CBOR of it - and writes it again as POI writes it; the `eTags` of a version it checks against
the content it writes, not against the one it was given. So the version with the offset, or with the key in CBOR that
is not deterministic, has the `eTags` of the version as published for WWCP_POI3: written again, it is that version;
as given, its canonical JSON has another digest, and WWCP_POI.TS, which hashes what it was given, finds no commit of
it. SPECIFICATION.md says how the content holds them: "Timestamps: UTC to the millisecond,
`yyyy-MM-ddTHH:mm:ss.fffZ`" (2, Written forms) and "Base64 of the deterministic CBOR of the public COSE key" (4.1);
of a new value a change set gives that a reader MUST refuse one written otherwise (4, New values), and WWCP_POI3 does
(`new-value-timestamp`, csharp-review 10). Of a version it says it of none. WWCP_POI.TS refuses them on purpose.

**Why it matters:** medium (interop). The two implementations disagree on whether a version is the one its `eTags`
and its commit name; and a reader of WWCP_POI3 holds as verified a document whose bytes no commit covers - the pattern
of D1 and D10.

**Fix:** say in SPECIFICATION.md, section 2, that a reader MUST refuse a value of the content not written as it says,
as section 4 says it of a new value; refuse it where WWCP_POI3 reads a key, in the words the vectors' `reason` names;
then remove D13 from `DEVIATIONS` of the generator.

**Fixed** in WWCP_POI `a425530`: `POIPublicKey.TryParse` reads a key as the content holds it, in the words of
WWCP_POI.TS - a timestamp a text written as `yyyy-MM-ddTHH:mm:ss.fffZ` and read back as written ("The notAfter of the
key '…' must be written as yyyy-MM-ddTHH:mm:ss.fffZ, not '…'!", "… must be a text!" for `null`), the key the
deterministic CBOR of its COSE key ("Invalid COSE key: Invalid deterministic CBOR: …"); SPECIFICATION.md 2, Written
forms, says that a reader MUST refuse a key of a party written otherwise, and the decisions of its README say so.
`KeyWrittenFormsTests` holds it. Both refuse all four vectors for what they are about.

**Covered since:** other values of a version written otherwise, which WWCP_POI3 takes as well and WWCP_POI.TS refuses
since `5c534d4` - a `created` with an offset among them, a property of a key POI does not read, a key naming its JSON-LD
context, keys out of their order -: [D15](#d15-content-as-held).


<a id="d14-body-malformed"></a>
## D14. ✅ A conformity assessment body WWCP_POI3 refuses to read is taken

**Vectors:** `version-body-certificate-not-notified`, `version-body-number-three-digits`,
`version-body-notified-for-empty` and `version-body-notified-for-twice` (`poi-refusals.json`): the head of the frozen
run, without its `eTags`, with the body `PTB` - notified for `MID` as `0102` - changed. WWCP_POI3 refuses each in the
words its `reason` names; WWCP_POI.TS takes all four:

| Vector | The body | WWCP_POI3 |
|---|---|---|
| `version-body-certificate-not-notified` | its certificate `PTB-2026-0042` is issued under `CRA` | "The certificate 'PTB-2026-0042' is issued under the legislation 'CRA', which the conformity assessment body 'PTB' is not notified for!" |
| `version-body-number-three-digits` | its `notifiedBodyNumber` is `102` | "The notified body number '102' of the conformity assessment body 'PTB' must be four digits!" |
| `version-body-notified-for-empty` | its `notifiedFor` is `[ "", "MID" ]` | "A legislation the conformity assessment body 'PTB' is notified for must not be empty!" |
| `version-body-notified-for-twice` | its `notifiedFor` is `[ "MID", "MID" ]` | "… must not be given twice!" |

**Where:** the constructor of `ConformityAssessmentBody` of WWCP_POI3 checks them. `RoamingNetwork.parse` of
WWCP_POI.TS reads of a body its certificates (D9) and its keys (D12), not its `notifiedBodyNumber`, its `notifiedFor`
and what the legislation of a certificate of it must be. `docs/ConformityAssessmentBody.md` of WWCP_POI says each
rule, and the generator quotes it: "four digits, e.g. `0102`", "each once", "any other nonempty text", "one its body
is `notifiedFor`". WWCP_POI.TS found it porting WWCP_POI `d6b0127` (S31, S32); the vectors show it.

**Why it matters:** low. The `notifiedBodyNumber` and `notifiedFor` of a body are the RNO's (S32), and a certificate
enters a version only by a change set its body, or the RNO in its place, signs; but WWCP_POI.TS takes a roaming
network version that WWCP_POI refuses to read, and a station proof gives its verifier the certificates as they are.

**Fix:** refuse them where `RoamingNetwork.parse` reads a body, in the words of WWCP_POI3 and in its order - the
number, the legislations, then the certificates -; then remove D14 from `DEVIATIONS` of the generator.

**Fixed** in WWCP_POI.TS `4ff1fc2`, with its port of WWCP_POI `d6b0127` (S31, S32) and before the vectors: a body is
checked as the constructor of `ConformityAssessmentBody` checks it, in its words and its order - also a
`notifiedBodyNumber` that is no text and a `notifiedFor` that is no array of texts, before them. Both refuse all four
vectors for what they are about.

**Covered since:** a `notifiedFor` out of its ordinal order, which both took - WWCP_POI3 writing it sorted (its
constructor ordered it), WWCP_POI.TS hashing it as given, a value written otherwise, as in D13 -, both refuse since
WWCP_POI `8108522` and WWCP_POI.TS `9decdb5` (`version-body-notified-for-out-of-order`), and SPECIFICATION.md 2 says
so; two bodies of the same `notifiedBodyNumber` (S32), a number that is no text and legislations that are no array of
texts both refuse alike (`version-body-number-twice`, `version-body-number-not-a-text`,
`version-body-notified-for-not-texts`).


<a id="d15-content-as-held"></a>
## D15. ✅ A version written otherwise than the content holds it is taken, and written again

**Vectors:** the 27 `version-held-*` (`poi-refusals.json`): the head of the frozen run with one value written otherwise
than the content holds it (SPECIFICATION.md 2, Written forms) - with the `eTags` of the version as published where,
written again, it is that version, else without them. WWCP_POI.TS refuses each, since `5c534d4`, in the words its
`reason` names - "'<path>' is not written as the content holds it: <how>!", of a key and of an EV Taler merchant in the
words of where it reads them -; WWCP_POI3 takes all 27, the 10 with the `eTags` as published:

| Written otherwise | Vectors `version-held-*` | How the content holds it |
|---|---|---|
| what the content orders, out of its ordinal order | `bodies-out-of-order`, `signing-keys-out-of-order`, `identity-keys-out-of-order` (with the `eTags`), `payment-options-out-of-order` (`SMS`, `Cash`), `payment-options-ordinal` (`bitcoin`, `SMS`: alphabetical regardless of case), `evtaler-exchanges-out-of-order` | "its elements are in the order the content holds them in" |
| the texts of an ordered list untrimmed | `payment-options-untrimmed` (`' Cash'`) | "the texts of its elements are trimmed" |
| a list given empty | `payment-options-empty` (with the `eTags`), `signing-keys-empty`, `notified-for-none` | "a list without elements is left out" |
| a property given as `null` | `description-null` (with the `eTags`) | "a property without a value is left out" |
| an embedded object naming its JSON-LD context | `key-context` (with the `eTags`), `evtaler-context`, `evtaler-exchange-context` | "embedded, an object names no JSON-LD context" |
| a text in languages keyed otherwise | `name-language-upper-case` (`EN`), `name-language-unknown` (`xx`), `name-language-not-a-text` (`"de": 5`), all three with the `eTags`, `description-language-number` (`10`), `evtaler-exchange-name-language` | "a text in languages names each language as Styx writes it, in lower case, with a text" |
| a timestamp with an offset | `created-offset` (the same instant, `+02:00`, with the `eTags`) | "a timestamp is UTC to the millisecond, yyyy-MM-ddTHH:mm:ss.fffZ" |
| a property POI does not read | `key-property-unread`, `evtaler-property-unread`, `evtaler-exchange-property-unread` | "The public key '…' must not name the property 'x'!", "The EV Taler merchant must not name …", "The exchange '…' must not name …" |
| a URL without its scheme or untrimmed, a currency untrimmed | `evtaler-merchant-url-no-scheme`, `evtaler-merchant-url-untrimmed`, `evtaler-exchange-url-no-scheme`, `evtaler-exchange-currency-untrimmed` | "The merchant base URL '…' is written as '…'!", "The base URL '…' of the exchange '…' is written as '…'!", "The currency '…' of the exchange '…' is written as '…'!" |

**Where:** WWCP_POI3 reads a version into its entities (`RoamingNetwork.TryParse`) and writes it again in its own
form - ordered, trimmed, without what is empty or `null` and without the context of what is embedded, a text in
languages as Styx reads it (a language in any case or by its number, the rest left out without a word), a timestamp
in UTC, without a property it does not read, a URL with its scheme -, and checks the `eTags` of a version against the
content it writes, not against the one it was given, as in D13. WWCP_POI.TS hashes what it was given. SPECIFICATION.md 2
says how the content holds each ("Arrays are in the order the content holds them in", "every other one trimmed",
"Absent values are left out, also empty arrays", "also where the object is embedded and its JSON leaves `@context`
out", "multi-language texts keyed by the lower-case code of a known language", "UTC to the millisecond", "URLs with
their scheme"); that a reader MUST refuse a new value written otherwise (4, New values), and of a version a key of a
party (D13) and the `notifiedFor` of a body out of its order; of the rest of a version it says nothing. WWCP_POI.TS
refuses all of it since `5c534d4`, on Achim's decision of 2026-10-29, as D13 decided it for keys: what WWCP_POI takes
of a version and writes otherwise is refused. It found the cases probing WWCP_POI3 at `8108522` with 201 versions of
QA; the vectors show them.

**Why it matters:** medium (interop), as D13. The two implementations disagree on whether a version is the one its
`eTags` and its commit name - for WWCP_POI3, 10 of the vectors are the version as published -, and a reader of
WWCP_POI3 holds as verified a document whose bytes no commit covers.

**Fix:** say in SPECIFICATION.md 2 that a reader MUST refuse a version not written as the content holds it, as it
refuses a new value written otherwise; refuse it where WWCP_POI3 reads a version, in the words the vectors' `reason`
names; then remove D15 from `DEVIATIONS` of the generator.

**Fixed** in WWCP_POI `3de830a` and `1de4dff`: `RoamingNetwork.TryParse`, of JSON and of CBOR, writes the network it
read again and refuses it unless its canonical JSON is the one given, its `eTags` aside and its `@context` where it
names none (`RoamingNetwork.WrittenForm.cs`, `3de830a`), naming the first value written otherwise in the words of
WWCP_POI.TS, and where it has none "the content leaves it out" or "the content holds it as '…'"; a key of a party
naming a property a key does not have, an EV Taler merchant or exchange naming one, a base URL or a currency written
otherwise, are refused before, where they are read (`POIPartyKeys`, `EVTalerMerchant`, `1de4dff`), in the words of
WWCP_POI.TS as well - against `3de830a` alone, these seven vectors were refused in the generic words. SPECIFICATION.md
2, Written forms, says that a reader MUST refuse a version written otherwise; `VersionWrittenFormTests` holds it. Both
refuse all 27 vectors for what they are about.

**Not covered:** WWCP_POI3 compares all of the content. WWCP_POI.TS, since `fb0562f`, walks a version as WWCP_POI3
`3de830a` writes it again (`notWritten`, after `FirstNotWritten`), in its words: also data licenses given by their
identifications alone (`dataLicenseIds`), which WWCP_POI3 writes as `dataLicenses`, and a property no type writes,
"the content leaves it out"; a `lastChange` or the name of a party left out, an identification of a charging station
operator in upper case, a coordinate not as the double it is, a URL without its scheme, "the content holds it as '…'";
the seven of the table in its own words. Its commit probed it against WWCP_POI3 `3de830a` with 1257 versions of QA,
which hold no country, e-mail address or duration. No vector here shows these yet.


<a id="d16-tariff-id"></a>
## D16. ✅ A price statement naming a charging tariff not as `{operatorId}*T{suffix}` is taken

**Vector:** `sessionPrice-foreign-tariff` (`poi-verifier.json`): `POIPrices/foreign-tariff.chargy` of ChargyWebApp
`fc513cd`, "Genuine price naming a tariff outside this EVSE's references". Its price statement, signed by `DE*POI` with
its key for price statements, names the charging tariff `DE*POI*FOREIGN`: no identification of a charging tariff,
`{operatorId}*T{suffix}`, as the one of `DE*POI` in the proof is (`DE*POI*T1`). WWCP_POI3 refuses the statement as it
reads it, so that none of the evidence holds; WWCP_POI.TS took it, and refused only that its price applies to the EVSE:

| | `signatures` | `applicability` | `agreement`, `publication`, selected |
|---|---|---|---|
| WWCP_POI3, the vector | `invalid` | `invalid` | `missing`, `missing`, none |
| WWCP_POI.TS before `80afec7` | `valid` | `invalid` | `missing`, `missing`, none |

**Where:** `POIPriceStatus` of WWCP_POI3 reads every `chargingTariffId` of the prices of a price statement as a
`ChargingTariff_Id` ("The prices of a charging tariff need a valid 'chargingTariffId'!"), as it reads a tariff and every
reference to one in a version; `SessionPriceEvidence` then counts the statement as invalid ("A price statement is
invalid"). `PriceStatement.parse` of WWCP_POI.TS checked that it is a text. In a version, WWCP_POI.TS reads charging
tariffs as WWCP_POI3 does since `813e1d7`: both refuse a tariff named `DE*GEF*AC`, and the EVSE template naming it, in
the same words (`version-tariff-id-not-of-its-pattern` of `poi-refusals.json`: "Invalid charging tariff identification
'DE*GEF*AC'!").

SPECIFICATION.md named the pattern for the templates and groups of charging tariffs only (9.1, 9.3), not for a tariff
itself, and has a server take a price statement only when "every charging tariff it names is one of that operator"
(12.2). On Achim's decision of 2026-11-03 the pattern holds wherever a charging tariff is named, and WWCP_POI `89c5fa3`
says so: in section 2, "A charging tariff is identified as `ChargingTariff_Id`, `{operatorId}*T{suffix}`", also "of the
prices of a price statement (12.1)", and in 12.1, "A statement naming another text is no price statement and is refused
before its signature is looked at." The generator quotes both.

**Why it matters:** low. A statement naming such a tariff names none of the EVSE, so neither implementation lets its
price apply; but WWCP_POI.TS counts a statement as validly signed that WWCP_POI3 and a server (12.2) refuse to read, and
an app showing a driver which statements of the evidence hold shows otherwise than WWCP_POI3. The fixture itself was
meant to show a tariff outside the references of the EVSE; a tariff of the pattern, e.g. `DE*POI*T2`, would show that.

**Fix:** refuse, where `PriceStatement.parse` of WWCP_POI.TS reads the prices, a `chargingTariffId` that is no
`ChargingTariff_Id`, as `src/network/reading.ts` reads one in a version since `813e1d7`, in the words of WWCP_POI3; then
remove D16 from `DEVIATIONS` of the generator.

**Fixed** in WWCP_POI.TS `80afec7`: `PriceStatement.parse` reads the price status as `ChargingPrices.TryParse` and
`ChargingTariffPrices.TryParse` of WWCP_POI3 read it, in their words and order, under "Invalid price status of the
price statement: " as `RoamingNetworkPriceStatement.TryParse` gives it - for `DE*POI*FOREIGN`, "The prices of a charging
tariff need a valid 'chargingTariffId'!". Both give the vector's result.

Since `80afec7` both refuse more of the price status of a statement, in the same words, which SPECIFICATION.md 12.1
says since WWCP_POI `6bd1bc1`: a property it does not hold, another JSON-LD context, its prices not an array, the prices
of a tariff not an object, without elements, an element that is no object or has no price component, a tariff named
twice, also in another spelling, a statement without a price status. The 13 `priceStatement-*` vectors of
`poi-refusals.json` added with them show each, among them the tariff identification of D16 itself
(`priceStatement-tariff-id-not-of-its-pattern`), patched from a price statement of the frozen run: no patch leaves its
signature valid, so each names the words both refuse it in as it is read.

**Since WWCP_POI `5a72313`**, on Achim's decision of 2026-11-05, the elements of the prices of a tariff are written as a
charging tariff holds them (SPECIFICATION.md 12.1), as a version holds the elements of a tariff (section 2): an element,
a price component or restrictions naming a property their type does not define, a number given as a text, the days of
the week out of their order, the JSON-LD context of an embedded object are refused before the signature is looked at,
in the words of the written form of a version - "'elements[0].restrictions.maxStateOfCharge' of the prices of the
charging tariff 'DE*GEF*T_DC' is not written as a charging tariff holds it: the content leaves it out!"
(`ChargingTariffPrices.TryParse`, `FirstNotWritten`). Before, both read an element as `ChargingTariffElement.TryParse`
reads it, passing over a property it does not know: a restriction a reader did not know did not restrict the price for
it, and two readers priced one session differently. The 6 `priceStatement-*` added with it show each
(`-tariff-element-restriction-unknown`, `-tariff-element-property-unknown`, `-tariff-price-component-property-unknown`,
`-tariff-element-restriction-number-text`, `-tariff-element-days-out-of-order`, `-tariff-element-context`), patched as
the 13 before; and `sessionPrice-conditional-price` of ChargyWebApp, its element restricted by `max_kwh`, the name of
OCPI for POI's `maxEnergy`, is no price statement now: none of its evidence holds, as of `sessionPrice-foreign-tariff`.
WWCP_POI.TS took the 6 as it read them and gave the former result of the 7th before `ce88620`, which refuses them in
the same words, under "Invalid price status of the price statement: " (`tariffPrices` of `src/proofs/priceStatement.ts`
with `notWritten` of the written form), with [D18](#d18-restrictions).

What the two counterexamples of ChargyWebApp meant, the documents the generator makes show (`chargy/POIPrices`,
since WWCPPOIConformanceTests made them, every signature deterministic): `sessionPrice-tariff-of-another-evse`, a
price of `DE*POI*T2`, a tariff of the operator's pattern none of the references of the EVSE names - its signature holds,
no price of it applies, none is selected -, and `sessionPrice-conditional-element`, an element restricted by
`maxEnergy` - signed, agreed and published, its price selected, `unsupported`, without a rate. Both give each alike.


<a id="d17-time-zones"></a>
## D17. ✅ A charging pool naming a time zone that is none of a region of the IANA time zone database is taken

**Vectors:** the 10 `version-time-zone-*` of `poi-refusals.json`: QA with `DE*GEF*P1` in the time zone `CET`, `UTC`,
`Etc/GMT-1`, `US/Eastern`, `W. Europe Standard Time`, `europe/berlin`, `Europe/BERLIN`, `Europe/Atlantis` and
`Mars/Olympus`, and QA with an entity of every kind WWCP_POI3 reads, its charging pool template `DE*GEF*PT_STD` in the
time zone `CET`. WWCP_POI3 refuses each as it reads it, "The time zone 'CET' of the charging pool 'DE*GEF*P1' is no time
zone of a region of the IANA time zone database this reader knows!"; WWCP_POI.TS took each before `9cc620a`.

**Where:** SPECIFICATION.md 9.4 says since WWCP_POI `d1c41ca`, on Achim's decision of 2026-11-04 ([O5](#o5-time-zones)):
"The `timeZone` of a charging pool or of a charging pool template is a time zone of the IANA time zone database of one
of its regions (`Africa`, `America`, … `Pacific`), as the database writes it", "No name of another system …, none
without a region …, none in another case", and "A reader refuses a version a charging pool or template of which names
another, or one its time zone database does not know, rather than taking it as UTC". WWCP_POI3 checks it in the
constructors of `ChargingPool` and `ChargingPoolTemplate` (`POITimeZones.Known`): a name of a region,
`TimeZoneInfo.TryFindSystemTimeZoneById` finding it with `HasIanaId`, and its `Id` the name as given - .NET with ICU
finds `europe/berlin` on Windows as `Europe/Berlin`. `timeZoneNamed` of WWCP_POI.TS (`src/network/offers.ts`) found a
name as `Intl` does, without case, or a Windows name of its table (`timeZones.ts`), else UTC, and reading checked none.

**Why it matters:** medium (interop). A version WWCP_POI3 refuses is valid to WWCP_POI.TS; and before, a time zone the
platform did not know, e.g. `Europe/Berlin` under invariant globalization, made two offers overlapping in Berlin not
overlap, and priced a session otherwise.

**Fix:** refuse, where WWCP_POI.TS reads a charging pool and a charging pool template, a `timeZone` that is none of a
region, as the database writes it, or one the platform does not know, in the words of WWCP_POI3; drop the Windows names
of `timeZones.ts`. `Intl` takes a name without case and gives a link under another name (`Asia/Kolkata` as
`Asia/Calcutta` in Node 26), so it can not tell the case; `Temporal` can (`new Temporal.ZonedDateTime(0n,
name).timeZoneId`, `Europe/Berlin` for `europe/berlin`, `Asia/Kolkata` for `Asia/Kolkata`), but Node 22 and 24 have it
not. Then remove D17 from `DEVIATIONS` of the generator.

**Fixed** in WWCP_POI.TS `9cc620a`: `src/network/timeZones.ts` is the port of `POITimeZones` - `knownTimeZone`, a name
of a region which `Intl` knows, in the case of the database, and `unknownTimeZone` in the words of WWCP_POI3 - and
`poolListsConstruction` of `src/network/reading.ts` checks it as a charging pool and a charging pool template are
constructed, after their images, before their facilities, of the text trimmed, as `Time_Zone.TryParse` trims it. The
Windows names of `timeZones.ts` and the UTC of `timeZoneNamed` for a name it does not find are gone; a charging pool
without a time zone is in UTC as before. The case it tells by `Temporal` where the platform has it, its `timeZoneId`
the name as given; without it by the name `Intl` gives: the name itself is taken, the name only in another case refused
(`Europe/BERLIN`), another name - an older one `Intl` links to the one it gives - taken in any case. Both refuse the 10
vectors in the same words, and of 92 versions naming time zones WWCP_POI.TS compared with WWCP_POI3 `d1c41ca` - of
charging pools and templates, older names, parts of regions, other cases, whitespace, other JSON types, two faults of
one pool, the time zones of addresses - both give 90 alike, in the same words; the other 2 follow.

**Not covered:** a name the databases of the platforms of the harnesses know differently - `America/Ciudad_Juarez`
(2022g) and `Antarctica/Troll`, which .NET on Windows does not find through the ICU of Windows, so that WWCP_POI3 refuses
them there, and WWCP_POI.TS takes where the database of its platform knows them (Node 26, ICU 78.3, tzdata 2026e); an
older name in another case where the platform has no `Temporal` - Node 22 and 24, and browsers without it -, which
WWCP_POI.TS takes there (`Asia/KOLKATA`, `Europe/KYIV`), refuses with `Temporal` (Node 26), and SPECIFICATION.md 9.4
refuses ("none in another case"); and the rules of a time zone in databases of different age (SPECIFICATION.md 9.5,
point 7).


<a id="d18-restrictions"></a>
## D18. ✅ A version whose restrictions of a tariff element name a property their type does not define is taken

**Vector:** `version-held-restriction-unknown` of `poi-refusals.json`: QA with the element of `DE*GEF*T_AC` restricted
from 08:00 and to a state of charge of at most 80 %, `maxStateOfCharge`, a restriction no charging tariff has. WWCP_POI3
refuses it as it reads it, "'chargingStationOperators[0].chargingTariffs[0].elements[0].restrictions.maxStateOfCharge'
is not written as the content holds it: the content leaves it out!"; WWCP_POI.TS took it before `ce88620`.

**Where:** SPECIFICATION.md 2: "an entity and a value hold only the properties their type defines", and a reader
refuses a version written otherwise, e.g. with "a property its type does not define". `notWrittenAsHeld` of
WWCP_POI.TS (`src/network/writtenForm.ts`) knows the properties of an element of a tariff and of its price components,
not those of its restrictions, which it reads as `ChargingTariffRestrictions.TryParse` reads them, passing over a
property it does not know. Restrictions written otherwise else - a number given as a text, the days of the week out of
their order or in lower case, an embedded JSON-LD context, `null` - both refuse alike, in the same words: found by
probing 9 restrictions in a version, with the elements of a price status (12.1).

**Why it matters:** medium (interop). A version WWCP_POI3 refuses is valid to WWCP_POI.TS, which prices the sessions of
the tariff without the restriction it does not know.

**Fix:** the properties of restrictions in `writtenForm.ts`, as `ChargingTariffRestrictions` writes them: `startTime`,
`endTime`, `startDate`, `endDate`, `minEnergy`, `maxEnergy`, `minCurrent`, `maxCurrent`, `minPower`, `maxPower`,
`minDuration`, `maxDuration`, `daysOfWeek`, `reservation`. It was not pinned in `DEVIATIONS` of the generator: it was
to be fixed with the elements of a price status (12.1), whose vectors a patched statement shows refused only, never
taken, so that a marker of WWCP_POI.TS could not hold them.

**Fixed** in WWCP_POI.TS `ce88620`: the written form of `src/network/writtenForm.ts` knows the restrictions of an
element, `startTime` to `reservation`, as `ChargingTariffRestrictions` writes them; and `tariffPrices` of
`src/proofs/priceStatement.ts` compares the elements of the prices of a tariff in a price statement with it, as WWCP_POI3
`5a72313` does (12.1). Both refuse the vector, and the 6 of the elements of a price status, in the same words;
`sessionPrice-conditional-price` gives the same result in both.


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
- of the frozen run of the C# examples: the ETags of 14 versions, the identifications of 55 commits and 8 checkpoints,
  6 commit proofs against their checkpoints, the digests and chains of 8 price statements, 2 trust anchors and their QR
  codes, 6 station proofs (root, and verified against the trust anchor of their epoch), and the **replay of the whole
  history of QA commit by commit**: every change set of both epochs applied with its owners' signatures checked, the
  checkpoints 0 to 6 of epoch 1, the genesis of epoch 2, epoch 2 up to the head;
- the refusal of 296 changed documents: commits, checkpoints, versions, commit proofs, station proofs, price statements
  and trust anchors; among them a price statement whose price status is none, refused as it is read, in the same words
  ([D16](#d16-tariff-id)), a price statement naming its EVSE in another spelling, `DE*GEF*E11` for `DE*GEF*E1*1`,
  and a checkpoint naming two statements of one EVSE and sequence, in two spellings or of two prices, a split view
  (12.1, 12.3; WWCP_POI `4680d99`, WWCP_POI.TS `6bcf7f5`), each refused by WWCP_POI3 as a history takes it and by
  WWCP_POI.TS as a client checks it, in the same words; a station proof naming another revision than its attestations
  (D2), a change set naming `rebasedFrom` rightly with a change without `oldValue`, which a rebase may have overwritten
  a concurrent change with (csharp-review 12; WWCP_POI `1717ee2`, WWCP_POI.TS `4e4ec38`), and versions naming twice an
  identification
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
  without case (WWCP_POI.TS since `1f0d9c7`, D9), and versions naming an EV Taler merchant of a charging station
  operator WWCP_POI does not read - its base URL not HTTPS, naming a user, with a query or not ending in `/`, its
  public key in lower case or with its last 4 bits set, no exchange or one twice; of an exchange its base URL not
  HTTPS, its master public key in lower case, the currency `XXX` or no name - and a charging pool naming the payment
  option `EVTaler` while its operator names no merchant (EV Taler, phase 1; WWCP_POI `ec3dace`, WWCP_POI.TS
  `0aaf713`), refused in the same words, and a version naming a signing key of a usage POI does not know
  (WWCP_POI.TS since `37b34f2`, D12), and a version naming a key not written as POI writes it - its `notAfter` with
  an offset, of a date only or `null`, its key in CBOR that is not deterministic (WWCP_POI since `a425530`, D13), and a
  version naming a conformity assessment body WWCP_POI does not read - a certificate under a legislation it is not
  notified for, a `notifiedBodyNumber` not of four digits, a `notifiedFor` empty or given twice (WWCP_POI.TS since
  `4ff1fc2`, D14), out of its ordinal order (WWCP_POI since `8108522`, WWCP_POI.TS since `9decdb5`), a number that is no
  text, legislations that are no array of texts, the number of another body (S32), and a version not written as the
  content holds it - out of order, untrimmed, an empty array or `null` left out, an embedded JSON-LD context, a text in
  languages keyed otherwise, a timestamp with an offset, a property a key or an EV Taler merchant does not have, a URL
  without its scheme (WWCP_POI since `3de830a` and `1de4dff`, WWCP_POI.TS since `5c534d4`, D15), and a version naming
  a charging tariff by no identification of a charging tariff, `{operatorId}*T{suffix}` (WWCP_POI.TS since `813e1d7`,
  [D16](#d16-tariff-id)), and the elements of the prices of a tariff in a price statement written otherwise than a
  charging tariff holds them, refused before the signature (12.1; WWCP_POI `5a72313`, WWCP_POI.TS `ce88620`); and 142
  versions read as WWCP_POI3 reads them, as WWCP_POI.TS does since `813e1d7`, `2cbfe60`, `7c4d16e`, `9cc620a` and
  `ce88620` (`version-read-*`, `version-ref-*`, `version-held-*` of those, `version-offers-*`,
  `version-meter-key-*`, `version-time-zone-*`),
  refused in the same words: JSON types, missing properties and values of the network, its operator and its parties,
  of pools, stations, EVSEs, connectors, meters and their templates, of identifications, tariffs, offers and discounts,
  and what the constructor of an operator, a model, a provider, a grid or a parking operator refuses of what it read;
  the references the constructor of the network checks - a manufacturer, a model, a hardware revision, a release, a
  certificate, a grid connection point, a parking space, a station or a maintainer it does not have, an EVSE above its
  model, a meter naming the certificate of a station model or a signature method its model does not have, a provider
  twice, a key of two parties -; values written otherwise than the content holds them - a `lastChange` or a name
  WWCP_POI3 makes up, a number, a boolean or a text given as another JSON type, a duration, opening times, NUTS codes,
  an address and its country -; two offers of an operator overlapping at an EVSE (9.4), by a group, the operator or a
  group of pools, for sessions or providers both apply to, at the end of one and the beginning of the other, by their
  opening times, in the time zone `Europe/Berlin` and across its change to daylight saving time ([O5](#o5-time-zones));
  a charging pool or template naming a time zone that is none of a region of the IANA time zone database as it writes
  it, or one the platform does not know (9.4, [D17](#d17-time-zones));
  and public keys of energy meters BouncyCastle does not make - not DER, a point not on its curve or of another
  encoding, an RSA key of an even exponent, an Ed25519 point of small order - or with certificates not of the key, not
  issued by the next one, or not DER;
- all 25 trust vectors: a valid proof, expired attestations, attestations of the future (D3), one holder only
  (also twice), a key that may not sign for the party, a signing key expired before it attested and one that ended
  after it attested, a key certified by another holder's identity key, an uncertified key, other identity keys pinned,
  the quorum of the key statement above the one of the trust anchor, an attestation of another network, a changed
  entity, a wrong signature, a subject attestation and one in the role of a witness counted for the quorum (D4, D5), a
  certificate and a key statement of another roaming network operator (D6), attestations without `validUntil`
  ([O4](#o4-no-valid-until)), valid for a day, and valid longer; and the holders of a quorum as the trust anchor names
  them (csharp-review 1), two identity keys of Alpha one holder, a key statement naming one of them as Beta's, and a key
  the statement does not name counted for the holder the trust anchor names;
- all 75 replays of `poi-histories.json`: histories the generator made and signed
  with keys whose seeds it gives (the Ed25519 keys of section 6, and Ed25519, Ed448 and ES256 keys of its own), every
  refusal with its control, the document refused but for what it is about, taken in its place: who signs in place of a
  party without keys and with which usages (csharp-review 13), who states a certificate (15), releases and certificates
  identified under their owners, the prefix in another case too (S36), lastChange of what embeds
  a changed EVSE (8), old values, also `150000.0` for `150000`, and rebases with and without them (12), stamped with the lastChange of the
  head they were created before, no lastChange going back (S5), a signing key
  expired before the `createdAt`, also besides a valid one of its owner (D8), and one removed in the version before (3,
  in a linear history), new values with a
  JSON-LD context, out of their order or with a timestamp not to the millisecond (10), a withdrawal together with what
  names it (18), certificates of models in hardware revisions and firmware versions, of stations and of meters (16, 17),
  the EV Taler merchant of a charging station operator signed by its key for payments, not by one for the party or for
  infrastructure, nor by the roaming network operator in place of an operator with signing keys, and a charging pool
  naming the payment option `EVTaler` only with it, checked after the last change of a change set: both added in one,
  in either order, both removed in one, the merchant first, but neither the pool naming it without the merchant nor the
  merchant removed while the pool names it (EV Taler, phase 1; WWCP_POI `ec3dace`, WWCP_POI.TS `0aaf713`), and three
  epochs, the first checkpoint of the third one signed with an algorithm of the second one only, and with one
  of neither (14); where both word a refusal alike, `reason` names it. And the 13 WWCP_POI.TS left to WWCP_POI before,
  which held WWCP_POI3 alone (`notApplicable`): the references a version holds, which WWCP_POI.TS checks since
  `813e1d7` - a station in a firmware version its model does not have, of a hardware revision its certificate does not
  cover, a certificate of the other kind named by a station or a meter, a meter its station's certificate was not
  issued with (16, 17), a manufacturer or a model withdrawn while a station names it (18), an EVSE above the maximum
  power of its model, a model lowered below an EVSE naming it, a meter signing with a method its model does not name
  (19) -, and the changes of a group of an e-mobility provider and of a grid connection point, which it applies since
  `1946013` - a provider renaming, after it removed its group, the operator's group of the same identification (9), and
  a grid connection point the roaming network operator adds in place of a grid operator without keys (13). And the
  entities a party embeds, which WWCP_POI.TS applies since `1946013` (4.1): a charging tariff offer of a charging station
  operator signed for tariffs, not for infrastructure, and none covering an EVSE another one covers for the same
  sessions at the same times (9.4); the EVSE group, the charging tariff offer, the charging station group and the
  charging pool group of an e-mobility provider, signed by it, not by the operator of its prefix; a grid connection
  point the roaming network operator hands on in place of a grid operator without keys to a charging station operator,
  in one change set with a change of it, the change after the handing on its new maintainer's, the one before still the
  grid operator's (9); the parking garage, space and product of a parking operator, the product without timestamps, and
  the parking space of a charging station operator, each signed by its own party only;
- all 48 vectors of the QI-Digital documents of example A14 (`poi-qidigital.json`): the two certificates of
  conformity of the PTB, the declaration of conformity of SAALE and the calibration certificate of EM-LAB, each verified
  against QA at the time of the run, signed with ML-DSA-65 and ES256; the declaration against both certificates it names,
  also one whose `@id` is written in lower case (identifications are compared without case); both certificates covering
  the meter of `DE*GEF*E2*1`; and refused, each with its control and its `reason`: changed after it was signed, not
  signed, naming a key of another party, an unknown property, another JSON-LD context, a timestamp with an offset, a
  coverage factor without its uncertainty, a certificate of module D naming a model and one of module B naming a
  manufacturer, a legislation its body is not notified for, a performance location written otherwise, a text in no
  language and one that is no text ([D10](#d10-text-of-no-language)); against QA
  changed - another notified body number, the firmware of the certificate no longer one of its model, the meter updated
  since, without the laboratory, its key for certificates only for itself or ended before it signed, without the key
  SAALE signed with -; after the approval of the quality system and after the laboratory's key ended; the declaration
  against a certificate it does not name, of another body, module or legislation, not covering its firmware, approving
  the quality system of another manufacturer; a meter the certificates do not cover, also the meter updated since; and a
  whole number beyond Int64, which both refuse in words of their own: WWCP_POI3 while reading the quantity, WWCP_POI.TS
  when it writes the signature input. And a calibration certificate of a charging station the generator signs, taken
  against QA giving EM-LAB its key, refused against QA without it, and against QA giving the station another serial
  number, or none ([D11](#d11-station-serial-number));
- all 106 vectors of the verifier extensions of WWCP_POI.TS 0.2.0 (`poi-verifier.json`, experimental), of the
  fixtures of ChargyWebApp `fc513cd`, each normalized to what both give: the key of the meter of an EVSE a station
  proof gives, historical meter evidence of archived and witnessed checkpoints, session prices verdict by verdict, also
  of a price statement naming a charging tariff not as `{operatorId}*T{suffix}`, refused as read (WWCP_POI.TS since
  `80afec7`, [D16](#d16-tariff-id)), receipts of witnesses under the policy a verifier accepted, trust transitions, the keys a CPO signs charging
  documents with, policy identities, key statement digests, offer hashes and the digests of receipts; and 32 refusals,
  each against its control, 31 in the words of the `reason` both name: a meter key asked for ambiguously, by an unknown
  identification or of another meter, serial number or EVSE, or read as a COSE key it is not, historical evidence of conflicting assignments, of another
  period, of a tampered checkpoint or without what the local policy requires, a price of another EVSE, started after
  the verification or before the key statement, a trust transition without a quorum, tampered, out of order or accepted
  before it was signed, keys of a CPO for prices only, of another CPO or after the verification, a receipt of a private
  source.


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
### O2. ✅ `ETag.TryParse(String)` is less strict than `ETag.Parse(String)`

`WWCP_POI3/ChangeSet/ETag/ETag.cs`: `Parse` refuses non-canonical Base64 digests, `TryParse` (`:224`) does not check
the round trip. Read in the code, not shown by a vector: the text form of an ETag is C# API, no wire format both
implementations share.

**Closed** in WWCP_POI `7ee8c7d`: `TryParse(String)` reads the four parts with `FromTextParts`, as `Parse(String)` does,
and refuses what it refuses, in its words. It took a Base64 digest with whitespace in it, or with the two unused bits of
its last character set, which `Convert.FromBase64String` decodes to the same bytes
(`ETagTests.The_text_form_is_read_by_TryParse_as_strictly_as_by_Parse`, red without the change). Nothing in WWCP_POI3
calls it; the ETags of JSON and CBOR are read by `Parse(JToken)` and `Parse(CBORValue)`.

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

<a id="o5-time-zones"></a>
### O5. ✅ Whether offers overlap depends on the time zones of the platform

WWCP_POI3 compares the offers of an operator in the time zone of the EVSE's charging pool, as
`TimeZoneInfo.TryFindSystemTimeZoneById` finds it, else in UTC (`ChargingStationOperator.Offers.cs`). What it finds is
the platform's: under invariant globalization .NET on Windows finds no IANA name, so that `Europe/Berlin` is UTC there,
and two offers overlapping in Berlin do not - `version-offers-overlap-time-zone` and `-daylight-saving` were taken by the
C# harness, which ran with `InvariantGlobalization` until then; and .NET on Linux finds `CET`, on Windows it does not
(WWCP_POI.TS `7c4d16e`, which finds an IANA or a Windows name as `TimeZoneInfo` does with ICU, `timeZones.ts`). A
version may so be valid on one server and invalid on another. The C# harness runs WWCP_POI3 with ICU now, as a server
does, and in the invariant culture, so that its words are those of every machine (`Directory.Build.props`,
`VectorFiles.cs`). Open: whether SPECIFICATION.md names the time zones a reader knows, and what a version naming
another one is.

**Decided** in WWCP_POI `d1c41ca`, by Achim on 2026-11-04: SPECIFICATION.md 9.4 names them - a time zone of a region
of the IANA time zone database, as the database writes it - and a reader refuses a version naming another, or one its
database does not know, rather than taking it as UTC; how old its database is stays open (9.5, point 7). WWCP_POI3
refuses them (`POITimeZones`), WWCP_POI.TS since `9cc620a` ([D17](#d17-time-zones)). A server running WWCP_POI3 on Windows under
invariant globalization refuses every version naming a time zone now, in place of comparing its offers in UTC.

**Not covered** by the vectors of reading: a change set of an e-mobility provider making two of its offers overlap
(`NewProviderOfferOverlap`), which needs a history signed anew; a decimal
with places in a `reason`, which WWCP_POI3 words in the culture of its machine; the `(Parameter '...')` .NET appends,
which names a parameter of a constructor; and what WWCP_POI.TS lists as agreed differences of its probes against
WWCP_POI3 at `89d2e02` (identifications of the network given as numbers, messages of the CBOR and COSE libraries, a
number with an exponent).


## The findings of csharp-review and their vectors

What of the 23 findings of *csharp-review* a verifier reaches, and which vectors hold the implementations to it. All are
fixed in WWCP_POI, and 23 in WWCP_POI.TS as well ([D11](#d11-station-serial-number)); what is a server's (a witness,
its journal, the clock taking a change set, change sets waiting, rebasing and merging) no verifier vector reaches.
Most findings needed a history signed anew, which the keys of the frozen run, random and private, do not allow:
`poi-histories.json` holds small histories the generator signs itself (the replays named below are of it), every
refusal with its control. Every vector below holds both implementations: the 13 replays WWCP_POI.TS left to WWCP_POI
(`notApplicable`), as its review said, hold it as well - the references a version holds, which it checks since
`813e1d7`, and the changes of a group of an e-mobility provider and of a grid connection point, which it applies since
`1946013`.

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
| 9 | A provider's change of an operator's group, by a stale owner record | `owner-of-what-was-removed`; a grid connection point handed on within a change set, `grid-connection-point-handed-on`, `grid-connection-point-handed-on-unsigned-by-its-maintainer`, `grid-connection-point-named-then-handed-on` | Energy meter templates and groups: there a stale record reaches only changes that applying refuses, in both, so no vector tells the owner rule from it. |
| 10 | What a signed change set says is not what the content holds | `new-value-context`, `new-value-keys-out-of-order`, `new-value-timestamp`; the replay of the run takes the values of its change sets as the content holds them | The written forms WWCP_POI.TS can not tell without the types of the values (an identification in another case, a country, a URL without its scheme, …) end in other afterETags there: refused as well, but for that. |
| 11 | Epoch 1 checkpoints name their epoch | `checkpoint-epoch` (`poi-refusals.json`); every checkpoint of the run and of `history-epochs` | |
| 12 | A change without `oldValue` is not checked at all | `old-value-other`, `old-value-decimal` (`150000.0` for `150000`), `old-value-none`, `rebased-with-old-values`, `rebased-without-old-value`, `rebased-add`; `changeSet-rebased-without-old-value` (`poi-refusals.json`) | The rebase itself (`TryRebase`) is a server's. |
| 13 | The RNO can not sign in place of a body or grid operator without keys | `rno-states-certificate`, `rno-states-certificate-with-keys-for-certificates`, `rno-states-certificate-with-keys-for-tariffs`, `rno-states-certificate-one-holder`; `rno-adds-grid-connection-point`, `rno-adds-grid-connection-point-with-keys-for-tariffs` | The models of a manufacturer without keys a version names from before: a manufacturer is added with keys now. |
| 14 | The first checkpoint of a later epoch takes signatures of any algorithm | `epoch-first-checkpoint-algorithms-of-either`, `epoch-first-checkpoint-algorithm-of-neither`, `epoch-later-checkpoint-algorithm-of-before`, `epochs` | A snapshot of the third epoch naming the profiles of the second (`previousProfiles`): the replays start their epochs themselves. |
| 15 | Who stated a certificate can not be told once its body has keys | `rno-states-certificate-unsaid`, `body-certificate-said-by-rno`, `body-changes-certificate-said-by-rno`, `body-states-certificate-itself` | What a verifier tells of a station proof, the `statedBy` of its certificates: the vectors check what a proof is, not what an app shows of it. |
| 16 | A certificate is for a version of a model, but no station or meter names one | `parties-models-and-certificates`, `parties-station-and-meter`; `station-firmware-of-no-model`, `station-revision-not-certified` | Templates naming them: the generator calculates no effective content of templates. |
| 17 | An energy meter names the certificate of a station model, and has none of its own | `parties-station-and-meter`; `station-certificate-of-a-meter`, `meter-certificate-of-a-station`, `meter-not-of-the-certificate` | |
| 18 | What one party names blocks what another party withdraws | `withdrawn-with-what-names-it`; `withdrawn-while-named-party`, `withdrawn-while-named-model` | |
| 19 | Smaller points | The quorum of a trust anchor by holders (see 1); certificates and a key statement of another operator, `trust-certificate-operator`, `trust-statement-operator` ([D6](#d6-foreign-operator)); a conformity assessment body and a grid operator added without keys, `parties-added`; what a model rates, `evse-above-its-model`, `model-below-what-names-it`, `meter-signing-not-as-its-model` | The roles of checkpoint signatures and the key statements the examples trust are the verifier's and the examples'; which price statements an epoch takes along, decided in WWCP_POI `1964903`, is a server's; the other data of a model, which describe it and are compared with nothing, no vector reaches, nor a station above its model by a template; building the examples and the dependencies of COSE.TS no vector reaches. |
| 20 | Custom data: numbers as binary floating-point numbers, timestamps in the time zone of the server | `spec-2-custom-data-decimals`, `-integers`, `-texts`, `-nested` (`poi-specification.json`) | |
| 21 | The custom data of an address is lost | `spec-2-custom-data-address` (`poi-specification.json`) | |
| 22 | A peer starting from a snapshot passes over attestations it can not read | `anchored-head-unreadable-attestation`, `anchored-head-attestation-not-an-object` (`poi-histories.json`), against `TryFromAnchoredSnapshot`, which the peer uses | The peer itself, its connection and what it asks for |
| 23 | The calibration certificate of a charging station is compared with its own serial number | `qid-calibration-station`, `qid-calibration-station-replaced`, `qid-calibration-station-without-serial-number` ([D11](#d11-station-serial-number)): a calibration certificate of a station the generator signs, with a key QA patched gives EM-LAB | |

No finding of the review, and not covered either: of the texts WWCP_POI reads as given since `c31e5e3` and `3672b06`,
that it takes them so - whitespace inside, case, a leading U+FEFF, which `Char.IsWhiteSpace` does not take for
whitespace -, as `poi-refusals.json` holds refusals only; and a change set leading to a text it refuses, which a
history of `poi-histories.json` could hold.
