# Review of the C# implementation (WWCP_POI at 801bbce)

Written by [WWCP_POI.TS](https://github.com/OpenChargingCloud/WWCP_POI.TS) while porting, and kept in its `docs/` up to
its `b9c786e`: "this port" and "the TypeScript port" are WWCP_POI.TS. Its findings are cited as *csharp-review N*.

What porting WWCP POI 3 to TypeScript turned up in the C# implementation and the specification: logical errors,
verification weaknesses, and places where code and specification disagree. Paths are relative to
[WWCP_POI](https://github.com/OpenChargingCloud/WWCP_POI) at commit `801bbce` (2026-10-24, charging station and energy
meter manufacturers as parties with their models), Styx at `91901a9`, which the RoamingHubCLI pins with it (`a0c1841`).
The first review was of `2d9511d`, the second of `bbd4cbd`; every finding was checked again against `801bbce`, and the
code added since, manufacturers as parties, their models and the references to them, was reviewed as well.

Each finding says how it was established:

- **demonstrated**: shown with data, a C# program run against the C# implementation or the TypeScript port;
- **confirmed**: the exact code path was read;
- **plausible**: the code path was read in parts; the scenario needs conditions that were not set up.

Since this review, this repository holds the C# implementation and this port to the same golden test vectors. Where the
two take or calculate different things, it is written down and pinned in
[implementation-deviations.md](implementation-deviations.md) (cited below as *D1* to *D8*): it demonstrates findings 6,
7, 19, 20 and 21 with vectors, and found two deviations more, a JSON reader for hashing that takes what is no JSON (D1)
and the revision of a station proof left unchecked (D2), both fixed in WWCP_POI `2c90847`. Since, it holds the fixed
findings with vectors as far as a verifier reaches them, replaying small histories it signs itself
(`poi-histories.json`; which finding which vectors hold, implementation-deviations.md lists), and found one deviation
more, of this port: a change set signed, besides by its owner, by a key not valid at its `createdAt` was taken here,
refused by WWCP_POI (D8, see 3), refused here as well since. This document stays the review of the C# implementation.

| # | Finding | Severity | Status | Since `bbd4cbd` |
|---|---|---|---|---|
| 1 | ✅ The holders counted for a quorum are named by the keys being counted | high | confirmed | unchanged; **fixed** in `3e32f48` |
| 2 | ✅ ECDSA twins of price statements: false split views, broken chains | high | demonstrated | unchanged, again demonstrated; **fixed** in `dbf39b0` |
| 3 | ✅ A removed or expired key still signs, through an older version | high | confirmed | unchanged; **fixed** in `f2ae688` |
| 4 | ✅ A change set counts as committed by its `@id` alone | medium-high | confirmed | unchanged; **fixed** in `bc3b1bd` |
| 5 | ✅ A witness signs the first checkpoint of a history started from a snapshot unchecked | medium-high | confirmed | unchanged; **fixed** in `c5cfc62` |
| 6 | ✅ A subject attestation verifies a whole proof | medium | demonstrated (D4, D5) | unchanged; **fixed** in `6e469a0`, as this port does |
| 7 | ✅ Attestations without `validUntil`, keys checked at a self-chosen `signedAt` | medium | demonstrated (D3) | unchanged; **fixed** in `be07037`, more than this port did |
| 8 | ✅ `lastChange` of what embeds a changed entity: code and specification disagree | medium (interop) | demonstrated | unchanged; **fixed** in `8e6a1fa`, the specification following the code |
| 9 | ✅ A provider's change of an operator's group, by a stale owner record | medium | demonstrated | unchanged; **fixed** in `850440a`, more than the review found |
| 10 | ✅ What a signed change set says is not what the content holds | low (interop) | demonstrated | unchanged; **fixed** in `80e4ccc`, more than the review found |
| 11 | ✅ Epoch 1 checkpoints name their epoch, the specification says they do not | low (interop) | demonstrated | unchanged; **fixed** in `9280f0b`, the specification following the code |
| 12 | ✅ A change without `oldValue` is not checked at all | low | confirmed | unchanged; the models as well; **fixed** in `1717ee2`, where it mattered, and in this port alike |
| 13 | ✅ The roaming network operator can not sign in place of a body or grid operator without keys | medium | demonstrated | unchanged, again demonstrated; **fixed** in `36bb176`, and in this port alike |
| 14 | ✅ The first checkpoint of a later epoch takes signatures of any algorithm | low | confirmed | unchanged; **fixed** in `65e658d`, and in this port alike |
| 15 | ✅ Who stated a certificate can not be told once its body has keys | low | confirmed | unchanged; **fixed** in `65e658d`, and in this port alike |
| 16 | ✅ A certificate is for a version of a model, but no station or meter names one of its model's | medium | confirmed | **new**; **fixed** in `7e0b0ac`, and in this port alike |
| 17 | ✅ An energy meter names the certificate of a station model, and has none of its own | medium | confirmed | **new**; **fixed** in `987fa26`, and in this port alike |
| 18 | ✅ What one party names blocks what another party withdraws | low | confirmed | **new**; **fixed** in `52f1172`, the specification following the code |
| 19 | Smaller points | low | confirmed | extended; **mostly fixed** in `65e658d`, the price statements of an epoch in `1964903`, one left open as a question of design |
| 20 | ✅ Custom data: numbers as binary floating-point numbers, timestamps in the time zone of the server | medium (interop) | confirmed | **new**, found fixing 10; **fixed** in Styx `06b592d3` |
| 21 | ✅ The custom data of an address is lost | low | confirmed | **new**, found fixing 10; **fixed** in Styx `06b592d3` |

✅ marks what WWCP_POI has fixed since; the finding stays as it was found, with how it was fixed.


## 1. ✅ The holders counted for a quorum are named by the keys being counted

**Where:** `WWCP_POI3/Proofs/RoamingNetworkKeyStatement.cs:622,635,651`,
`WWCP_POI3/Proofs/RoamingNetworkSigningKeyCertificate.cs:269,281`, `WWCP_POI3/Proofs/RoamingNetworkTrustAnchor.cs:46`;
the examples copy the pattern (`examples/csharp/exampleA1.cs`, step f).

A trust anchor pins the `@id`s of identity keys and a `minConsensus`, but not which holder holds which key; `holder` is no
part of the thumbprint. `TryVerify` counts `holders.Add(identityKey.HolderOrUnnamed)`, taking the holder from the
`identityKeys` of the very statement it verifies, or, for a key the statement does not name, from the operator's
`identityKeys` of the proof, which nothing verified yet. Certificates take the holder of the certifying identity key from
the same pool (`:269,281`).

**Scenario:** the specification allows a holder several identity keys ("e.g. identity keys of different `notBefore` and
`notAfter`", 4.1), and `CreateTrustAnchor` pins every key of the statement. Example A11 shows the case: AlphaOrg holds
its old and its new identity key at once, both named by the key statement of revision 14. AlphaOrg alone writes a key
statement naming its new key as held by "Beta", signs it with both keys: two holders. It certifies two of its own
signing keys, one labelled "Alpha", one "Beta", and attests a root of its choice with both: every verifier counts two
holders. The quorum, meant so that "no single company decides for the network", is met by one.

**Fix:** the trust anchor binds keys to holders (e.g. `keys` grouped per holder, `[[id, id], [id], [id]]`), and the
verifier takes holders from the anchor only; signatures by keys the verified statement does not name do not count.

**Fixed** in `3e32f48`, in context `v2` of the trust anchor (SPECIFICATION.md 4.1, 8.6):
- A trust anchor names the keys per holder, one entry each: the `@id` of its key, or the array of the `@id`s of its keys
  where it holds several (`"keys": ["a1…", ["b1…", "b2…"], "c1…"]`; in the URL the holders separated by `,`, the keys of
  one holder by `;`). A verifier takes each entry as a holder of its own; `CreateTrustAnchor` groups the keys as the key
  statement names their holders.
- The holders of a key statement are counted as the verifier knows them, never as the statement names them, and the
  statement must name the trusted keys so, or is refused (`RoamingNetworkKeyStatement.TryVerify(TrustedHolders, …)`).
  An attestation counts for the holder of the trusted identity key that certified its key, as the verifier knows it
  (`RoamingNetworkProof.Verify`), also for an anchored key the statement does not name.
- A key keeps its holder: a version naming a key of a party with another holder than the version before is refused.

`QuorumTests` of WWCP_POI hold the scenario above (`A_holder_does_not_count_twice_by_naming_its_key_as_another_s`), and
WWCPPOIConformanceTests holds it for both implementations (`trust-holder-renamed`, `trust-holder-unnamed-key`, and
`trust-holder-keys` taken). The TypeScript port does the same (`KeyStatement.verifyHolders`, `OperatorTrust`).


## 2. ✅ ECDSA twins of price statements: false split views, broken chains

**Where:** `WWCP_POI3/Proofs/RoamingNetworkPriceStatement.cs:250` (the digest covers `value`),
`WWCP_POI3/History/RoamingNetworkHistory.PriceStatements.cs:582-613` (statements compared by digest), `POST
~/history/priceStatements` needs no authorization (`WWCP_POI3/API/POI_API.PriceStatements.cs`),
`Styx/Illias/COSE/COSEAlgorithm.cs:1159,1374ff` (signing does not normalize `s`, verifying accepts any `s`).

An ECDSA signature `(r, s)` has a twin `(r, n − s)`, valid as well, which anybody computes without the key. The digest of
a price statement is the SHA-256 of its JSON *with its signature value*: the twin is a different statement of the same
sequence.

**Demonstrated** again at `801bbce` (`proofs/MakeProofs.cs.txt` of the run `csharp-801bbce` of the test vectors, its
output `MakeProofs-output.log`): a server joining `QA` from checkpoint 4 with the statements it names holds the genuine
statement 1 of `DE*GEF*E1*1`; the twin of it, which anybody makes from it, is refused as a split view of the operator.

```
price statement original: signature valid, sequence 0, digest 25a93a8691f67fc8bbea368d4a10e9f562379c7b96b1e315883280aba42ebf3e
price statement twin (r, n-s): signature valid, sequence 0, digest ad682ed917dccce9558c5d905201890bd7452f5ae3a6d9c565003c917c636d00
server of checkpoint 4 takes the genuine statement again, sequence 1, digest 3840c66f…: Known,
server of checkpoint 4 takes the twin of the statement, sequence 1, digest cc004833…: Refused, The EVSE 'DE*GEF*E1*1' has another price statement 1: two statements of one sequence are a split view!
```

So whoever relays statements (a peer, a proxy, anybody posting to a server first) can make a server take the twin;
then the genuine statement is refused as a split view of the operator, the next statement of the operator is refused
because its `previous` names the genuine digest, and the checkpoint names the twin, so the driver holding the genuine
statement, e.g. in the evidence of example A10, gets no proof of it (12.4). Epoch 2 of example A11 accepts ML-DSA only
and is not affected; every epoch accepting ECDSA is, epoch 1 of every roaming network among them. Commits and
checkpoints are not affected: their identifications leave signatures out.

**Fix:** digest and compare statements without `value` (the signed content), or require and produce low-S ECDSA
signatures where a signature value is hashed.

**Fixed** in `dbf39b0`, the first way: the digest of a price statement is the SHA-256 of its signature input, `value`
left out (SPECIFICATION.md 12.1; `RoamingNetworkPriceStatement.Digest`), as the identifications of commits and
checkpoints leave their signatures out. The twin is the same statement: a server taking it first takes the genuine one
as `Known` and the next one of the operator as following it (`PriceStatementTests`,
`The_ECDSA_twin_of_a_price_statement_is_the_same_statement`), and a checkpoint names the one digest both have. Without a
history to keep, in context `v1`. The TypeScript port calculates the same digest (`PriceStatement.digest`). The same
program against the run of `bc3b1bd` (`tests/vectors/csharp-bc3b1bd/proofs/MakeProofs-output.log`): the twin of the same
digest, which the server of checkpoint 4 takes as `Known`.


## 3. ✅ A removed or expired key still signs, through an older version

**Where:** `WWCP_POI3/History/RoamingNetworkHistory.cs:760-784` (`Commit`),
`WWCP_POI3/History/RoamingNetworkHistory.Persistence.cs` (`FindVersionFor`).

A change set is applied to whichever retained version its `beforeETags` name, not only to the head; its owners'
signatures are checked against *that* version and its `createdAt`, which the signer chooses; then the result is merged
into the head (`MergeTips`).

**Scenario:** the `infrastructure` key K of an operator leaks; the operator removes K at revision 10. The attacker takes
the public `beforeETags` of revision 9, chooses a `createdAt` within the validity of K, and signs a change of an EVSE with
K. It fits revision 9, is checked against revision 9, committed as a branch and merged into the head, as the head
changed only the operator's keys. The same holds for a signing key of the RNO whose certificate was removed: "a key is
revoked by removing its certificate" (8.6) does not hold for change sets. Example A11 replaces every key of `DE*GEF` at
revision 16 of epoch 1; within epoch 1, its old keys would still sign this way. The new epoch ends it: commits of epoch
1 are not taken in epoch 2.

**Fix:** a change set made for an older version must also be signed by keys valid in the head (or the tip it is merged
with) at the time it is taken, or `createdAt` must not lie before the `lastChange` of the head.

**Fixed** in `f2ae688` (SPECIFICATION.md 4.1, 4.2, 5.3, 8.6), the first way, without the second, which would refuse a
change set waiting for the signatures of a quorum (4.2) whenever anything else is committed meanwhile:
- **Merges:** two tips also conflict where a change set of the one since the merge base is signed by a key a best common
  ancestor names for a party, while the other tip, still having that party, no longer names it, or names it as not
  valid at the later of the change set's `createdAt` and the other version's `lastChange` (`RevokedKey`). Keys a branch
  added itself are not compared, so a branch adding a party or replacing a key and signing with it still merges; a
  party the other tip removed conflicts as its removal does. Every server makes the same merges, also of the commits
  of peers (`TryAppend`).
- **Commit:** a change set made for an older version is refused when it would conflict so with a tip it will be merged
  with ("Prepare it again for the head!").
- **When the server takes it:** `Commit` and `CoSign` count a key only when it is valid at `createdAt` and when the
  server takes it, by its clock, and refuse a `createdAt` later than then; so a `createdAt` chosen before lets an
  expired key sign nothing. Commits of peers are checked by what they say, not by that clock.

`MergeTests` of WWCP_POI hold the scenario above and its expiry variants. The TypeScript port takes no merges and
replays linear histories only, so nothing changes there. WWCPPOIConformanceTests holds both to what a linear history
asks: a key expired before the `createdAt` of a change set, or removed in the version before, signs nothing of it
(`key-expired`, `key-removed`); and found that this port took a change set signed by such a key besides its owner's
valid one, which WWCP_POI refuses (D8, `key-expired-besides`). It refuses it since, in the words of WWCP_POI: every
signature by a key of a party of the version is by one valid at the `createdAt` of the change set (`checkOwnership`, as
`TryGetSigners`), only a new identity key proving its possession may be one valid later (`tests/ownership.test.ts`).


## 4. ✅ A change set counts as committed by its `@id` alone

**Where:** `WWCP_POI3/History/RoamingNetworkHistory.cs:756` (`FindCommitted`), `:1797-1830` (`ChangeSetIds`,
including `metadata.rebasedFrom`).

A change set's `@id` is a random text its maker chooses, not a digest of its content. `Commit` answers
`AlreadyCommitted` for any change set whose `@id`, or one of its `rebasedFrom` ids, is known already, without comparing
contents.

**Scenario:** a change set X waits for the signatures of the RNO's holders (4.2), e.g. adding a party. Another party
commits a change set of its own, possibly with no changes at all, with `"@id": X`, or naming X in `rebasedFrom`. From then
on X is "committed", every further co-signature of the genuine X answers `AlreadyCommitted`, and X is never applied. This
contradicts 4.2: "a change set of the same `@id` saying something else is refused". The WebSocket of example A12 takes
change sets of authenticated senders (`commitChangeSet`), another way in.

**Fix:** identify change sets by the digest of their content without signatures (as commits are), or compare the content
of a change set found by its `@id`; refuse change sets without changes.

**Fixed** in `bc3b1bd` (SPECIFICATION.md 4, 4.2, 5.2, 5.3), the first way, so that nobody can take the `@id` of another
change set, not even of one waiting whose `@id` the list of change sets waiting tells (comparing contents only would
have refused the genuine one then):
- **Identification:** the `@id` of a change set is the SHA-256 of its canonical JSON with its `@context`, without `@id`
  and signatures, 64 lowercase hex digits, in every epoch (`RoamingNetworkChangeSet.ContentId`; `CreateChangeSet` and
  `TryRebase` set it). A change set identified otherwise is refused when read, and by `Commit`, `CoSign` and
  `TryAppend` before they look for it as committed; so is one without changes, and one named as the change set of a
  merge outside a merge commit, which alone is identified by its parents. The same `@id` is the same change set, so
  `AlreadyCommitted` answers only the change set itself.
- **Rebased:** `rebasedFrom` names each change set a rebased one was prepared from by its `@id`, `beforeETags` and
  `afterETags`; an entry counts only when that `@id` is the one of the rebased change set with these ETags and the
  entries before it, so everyone calculates it again, and a change set committed rebased answers the one it was
  prepared from as committed, and lets go of it waiting.

`CoSigningTests` of WWCP_POI hold the scenario: under the `@id` of the one waiting, naming it in `rebasedFrom`, or
without changes, another change set is refused, and the one waiting is committed once signed, told so once. The
TypeScript port checks the `@id` and `rebasedFrom` of every change set it reads (`ChangeSet.parse`,
`changeSetIdentification`) and refuses a commit with one parent whose change set has no changes or a merge
identification (`Commit.parse`); WWCPPOIConformanceTests holds both to the refusal vectors `changeSet-id`,
`changeSet-rebasedFrom`, `changeSet-without-changes` and `changeSet-merge-id`, against the new frozen run of `bc3b1bd`.


## 5. ✅ A witness signs the first checkpoint of a history started from a snapshot unchecked

**Where:** `WWCP_POI3/History/RoamingNetworkHistory.Checkpoints.cs:865` ("Only the first checkpoint of a history that
started from a snapshot can not be checked completely"), `:409-446` (`TryWitness` signs any checkpoint the history holds).

`TryWitness` claims "This history holds only checkpoints it checked, one per sequence, so a witness never signs two
different ones of the same sequence". A history started from a snapshot takes its first checkpoint without checking its
`commits`; `TryWitness` signs it all the same. A peer replaces its history by one started from a snapshot when the other
server answers `NotFound` (`Sync/RoamingNetworkPeer.cs`), and a peer whose history lacks the final checkpoint of an
epoch starts the next epoch "from the other server, as from its start" (11.4): so a witness could be led to sign a
second checkpoint of a sequence it signed before (plausible, not set up). Section 10.2: a witness signs only "after it
refused nothing of 10.1 in its own history, which it took commit by commit".

**Fix:** `TryWitness` refuses a checkpoint whose commits the history did not check, and a witness keeps the checkpoints
it signed across restarts, new histories and epochs.

**Fixed** in `c5cfc62` (SPECIFICATION.md 10.2, 10.5), both:
- **Checked only:** a history marks the checkpoint it takes without its commits, the first one of a history started from
  a snapshot (also when it is loaded again; after a compaction more strictly), and `TryWitness` refuses it.
- **A journal beyond the history:** a witness is its key and its journal (`RoamingNetworkWitness`,
  `RoamingNetworkWitnessJournal`, in memory or a file of one JSON line per checkpoint, written through before the
  signature is given), one per witness for every history it signs from. It refuses another checkpoint of a roaming
  network, epoch and sequence it signed; one the history signs from cannot tell is of the line signed last, as it does
  not hold that checkpoint, e.g. after the peer started it anew from a snapshot; and one of an epoch not starting from
  the final checkpoint it signed of the epoch before. Signing the same checkpoint again, e.g. with a new key, is
  taken.

`CheckpointTests` and `EpochTests` of WWCP_POI hold a history joined from a checkpoint snapshot, the journal read again
after a restart refusing another checkpoint of a sequence from another history, a history not holding the checkpoint
signed last, an epoch started from another final checkpoint, and a line written only partly. Examples A6, A9, A10 and
A11 sign through one witness per party, its journal in `witnesses/`; A6 shows a copy started anew and one joined from
a snapshot refused. A witness whose history was replaced in the middle of an epoch signs again in it only once it holds
the checkpoint it signed last, at the latest in the next epoch. The TypeScript port signs no checkpoints.


## 6. ✅ A subject attestation verifies a whole proof

**Where:** `WWCP_POI3/Proofs/RoamingNetworkProof.cs:252` (`AttestationsOf`), `:401` (`required == 1`).

An attestation with a `subject` (8.5) only has to match the digest of one entity; its root is not compared with the root
of the proof. With a quorum of one, the first such attestation verifies the whole proof, with whatever the proof gives
above that entity (the name of the network, its operator, the manufacturers and since `801bbce` the models of the
station and its meters, the transparency software releases and certificates of the meters, example A13); with a quorum,
subject and root attestations are counted
together. `role` and `signer` of attestations are not checked.

**Demonstrated** by the vectors `trust-subject` (D4) and `trust-role` (D5) of WWCPPOIConformanceTests: a proof whose
quorum of two holders is met by one root attestation and one of a subject, or by one in the role of a witness, is taken
by the C# implementation and refused by this port.

**Fix:** a subject attestation attests its subject only: count it for the subtree, never for the proof. The TypeScript
port counts root attestations only, in the role `roamingNetworkOperator`.

**Fixed** in `6e469a0` (SPECIFICATION.md 8.4 and 8.5): a proof is verified by attestations of its root in the role
`roamingNetworkOperator` only, with a quorum and without, as this port does. `VerifySubject` verifies the charging
station operator an attestation of a subject names, in the role `chargingStationOperator`, by the digest of the operator
as the proof gives it: that node with everything below it, nothing above it. The vectors `trust-subject` and
`trust-role` hold both implementations to it; WWCPPOIConformanceTests no longer lists D4 and D5 as deviations. This port
verifies no subject attestations.


## 7. ✅ Attestations without `validUntil`, keys checked at a self-chosen `signedAt`

**Where:** `WWCP_POI3/History/RoamingNetworkAttestation.cs:417-419`, `WWCP_POI3/Proofs/RoamingNetworkProof.cs`
(`CertifiedSigningKeyOf`), `WWCP_POI3/Proofs/RoamingNetworkPriceStatement.cs` (validity).

`IsValidAt` is `!ValidUntil.HasValue || Timestamp <= ValidUntil`: an attestation without `validUntil` is valid forever,
and one signed in the future is valid now. The signing key is checked at the attestation's own `signedAt`. A proof brings
its own certificates. An offline verifier therefore accepts, forever, an attestation by a signing key that was revoked
(its certificate removed, 8.6) or expired, back-dated into its validity. The same holds for price statements without
`validUntil`. Example A10 relies on bounded attestations (15 minutes) and checkpoints for what holds later: that is the
right pattern, but nothing enforces it.

**Demonstrated** by the vectors `stationProof-before-signed` and `trust-future` (D3) of WWCPPOIConformanceTests: a proof
checked a second before its attestations were signed is taken by the C# implementation. Attestations without
`validUntil` are taken by both, valid forever (`trust-no-valid-until`): requiring it is a matter for the specification.

**Fix:** require `validUntil` with a bounded lifetime, `signedAt ≤ at`, and the key valid at `at`. The TypeScript port
requires `signedAt ≤ at`.

**Fixed** in `be07037` (SPECIFICATION.md 8.5, 8.6, 12.1, 12.4), and in this port alike:
- **Bounded:** an attestation gives its `validUntil`, at most 24 hours after its `signedAt`
  (`RoamingNetworkAttestation.MaxValidity`); one without, or valid longer, is refused when it is read. `Create` and
  `Attest` sign one valid for 15 minutes unless told otherwise, and a history attests for at most a day
  (`AttestationValidity`). So no attestation outlives the day it was signed, also one of a key revoked since.
- **Signed before:** `IsValidAt` is `signedAt ≤ at ≤ validUntil`; an attestation of the future is no attestation now. A
  history takes an attestation of another server signed up to 5 minutes after its own clock (`MaxClockSkew`, as for
  change sets), and counts it once it was signed.
- **The key at `at`:** the signing key of an attestation counts when it is valid when it attested and at the time the
  proof is verified; a price statement, with a `validUntil` or without, is valid no longer than its key
  (`TryVerify(SigningKeys, …, At)`), and an operator replacing that key states its prices anew with the next one.

Price statements keep `validUntil` optional: without, a statement is valid until the next one of its entity, as its chain
says; its key bounds it. The vectors `stationProof-before-signed` and `trust-future` hold both implementations to it,
`trust-no-valid-until` is refused by both, and `trust-a-day`, `trust-too-long` and `trust-key-ended` are new;
WWCPPOIConformanceTests no longer lists D3 as a deviation.


## 8. ✅ `lastChange` of what embeds a changed entity: code and specification disagree

**Where:** `WWCP_POI3/RoamingNetwork/RoamingNetwork.InfrastructureChanges.cs:561,693-717` (`TouchParents`), likewise
`ProviderChanges.cs`, `OfferChanges.cs`, `GridChanges.cs`, `ParkingChanges.cs`, `EnergyMeterGroupChanges.cs`,
`TransparencySoftwareChanges.cs`, `TransparencySoftwareCertificateChanges.cs`, and new, `ModelChanges.cs` ("The
manufacturer embedding it changed with it"); `SPECIFICATION.md:174-176`.

The specification: a change set sets `lastChange` "of an entity when it is added … or when one of its own properties
changes; **not when only an entity it embeds changes**". The code sets it on the charging station, the charging pool
and the operator of a changed EVSE, on the operator of a changed energy meter template, on the manufacturer of a changed
model or release, on the body of a changed certificate. `docs/README.md`, `docs/TransparencySoftwareManufacturer.md`,
`docs/ConformityAssessmentBody.md` ("set to the `createdAt` of the change set by every change of it and of its releases")
and `WWCP_POI3_Tests/InfrastructureTests.cs` follow the code.

**Demonstrated:** the TypeScript port reproduces the `afterETags` of the commits of the examples only by doing what the
code does (e.g. revision 2 of epoch 1, the models of example A2, revision 10, the correction of example A5, and
revisions 5 to 7 of epoch 2, example A13). An
implementation following the specification calculates other ETags and refuses every such change set. One of the two
must change.

**Fixed** in `8e6a1fa` (SPECIFICATION.md section 4): the specification follows the code. A change set sets the
`lastChange` of every entity embedding one it adds, changes or removes, up to the roaming network, named there by kind;
`lastChange` tells when the representation of an entity, with everything it embeds, last changed, as its ETag does, and
the history tells what changed. Models, transparency software releases and certificates are named among what has no timestamps;
energy meters keep those of their new value. The README of WWCP_POI and the documents of the e-mobility provider and the
parking operator say the same, and `ChargingTariffOfferTests` and `TransparencyTests` now check the owners of a changed
offer and the body of a changed certificate as well. No implementation calculates other ETags than before: the frozen
runs, the test vectors and the TypeScript port stay as they are. `tests/lastChange.test.ts` of the port checks every
change set of both epochs of the run, and refuses `afterETags` calculated as the specification said before (revision 10
of epoch 1). WWCPPOIConformanceTests holds both implementations to it with a history it signs itself: an EVSE changed,
its station, pool and operator with it (`lastChange-and-old-value`), and refused, as the specification said before
(`lastChange-of-what-embeds-it`). The effective `lastChange` of 8.1 takes the one of a station or pool without templates as it is; it is not
older than those of its EVSEs and stations as long as the `createdAt` of the change sets grows, and where it does not,
e.g. after merges, the floors of section 8.8 (point 3) remain open.


## 9. ✅ A provider's change of an operator's group, by a stale owner record

**Where:** `WWCP_POI3/RoamingNetwork/RoamingNetwork.Ownership.cs:1144,1191` (`AddedProviderGroups`),
`RoamingNetwork.ProviderChanges.cs`.

Within one change set, an `Add` of a provider's group records the provider as its owner; a later `Remove` of it leaves the
record. A third change of the same group id is then owned by the provider, while applying it finds no provider group
and changes the operator's group of that id. It needs a provider id the group id type takes as the operator's (e.g.
`DE-XYZ` and `DE*XYZ`); network-wide uniqueness of group ids is checked only after the last change. The owner path was
read, the full scenario was not set up. `AddedEnergyMeterChildren` (`:1386-1452`) follows the same pattern for energy
meter templates and groups.

**Demonstrated** against `be07037`, then **fixed** in `850440a`. The provider `DE-GDF` alone signed a change set adding
its group `DE-GDF*EGHIGHWAY`, removing it, and renaming `DE*GDF*EGHIGHWAY`, the group of the charging station operator
`DE*GDF`: `TryCheckOwnership` took it, and `TryApplyChangeSet` renamed the operator's group. So did the change set in
which the roaming network operator removed the provider, with the group, in place of the `Remove`, signed by the provider
and the roaming network operator.

The owner records of a change set (`EarlierChanges`) now say who owns what its earlier changes added, the parent of the
`Add`, and that nobody owns what they removed, alone or with the party embedding it, until it is added anew; an owner
the version names counts only while no earlier change removed it. A change of a group is one of a provider's group while
a provider has it, as applying it decides (`IsProviderGroupChange`), else the operator its identification names signs
it. Energy meter templates and groups, charging tariff offers, parking entities and grid connection points follow the
same rule; there the stale record reached only changes that applying refused, as their `Add` refuses an identification
any owner has, and they are now refused by their owners already. More than the review found: a grid connection point
handed on or taken over by an earlier change is the new maintainer's for the changes after it, not the former one's.
SPECIFICATION.md section 4.1 says so ("Within a change set"), and 9.3 that a provider's and an operator's group may
share an identification within a change set. `ProviderGroupTests`, `EnergyMeterTemplateTests` and
`GridConnectionPointTests` hold it.

This port applies no change of a provider's group, nor of a grid connection point; its record of the energy meter
templates and groups an earlier change added reaches only changes that applying refuses. It stays as it is.
WWCPPOIConformanceTests holds WWCP_POI to the scenario of the provider's group (`owner-of-what-was-removed`).


## 10. ✅ What a signed change set says is not what the content holds

**Demonstrated:** a change set's values are parsed into the C# model and written anew; what ends in the content differs
from what was signed, and a reader applying change sets on JSON (as the TypeScript port does, and as section 4 describes
them) must know how:

- **`@context` dropped:** revision 13 of example A8 (`UpdateProperty` of `elements` of `DE*GEF*T_AC`) writes its
  `newValue` as `[{"@context": "…/chargingTariffElement/v1", "priceComponents": […]}]`, signed so; the content holds the
  elements without it. Section 1.1: an embedded object "does not" name its context.
- **Arrays reordered:** revision 15 of example A11 (`UpdateProperty` of `identityKeys` and `signingKeyCertificates` of
  `OCC`) gives the old keys first and the new ones after; the content holds them in the order of their `@id`s, the
  certificates in the order of the `@id`s of the signing keys they certify, then of the keys that signed them
  (`POIPublicKey.Ordered`, `RoamingNetworkSigningKeyCertificate.Ordered`; likewise energy meters and their public keys,
  data licenses). Section 2 orders "embedded entities" by their identifications; certificates have none, and keys and
  meters are not called entities there.

Harmless for the C# reader. **Fix:** state the order of every array of the content in section 2, and refuse a change set
whose values are not in it, so that what is signed is what is held.

An inventory of the readers and writers of the C# model found more than order and contexts: identifications in upper
case (`de*aaa` held as `DE*AAA`), countries as alpha-3 (`de` as `DEU`), timestamps converted to UTC and cut to the
millisecond, URLs given a scheme, language keys in lower case, unknown properties dropped, an empty array held as none,
and lists of predefined values sorted (`standards`, `features`, `vehicleTypes`, …). The port knew of two of them: every
other one made it calculate other `afterETags` than C# for a change set C# took. It also removed a JSON-LD context in
`customData`, which C# keeps.

**Fixed** in `80e4ccc` (SPECIFICATION.md 1.1, 2 "Written forms", 4 "New values"), as proposed and further: what a change
set gives is what the content holds. Every handler of a change reads the changed entity again and compares what it
writes with the new value, as canonical JSON - the property of an `UpdateProperty`, the entity of an `Add` without the
timestamps the change set sets, the element of an element change (`TryHeldAsGiven`, `FindHeld`) - and refuses a value
written otherwise, or one the content does not hold at all. `CreateChangeSet` and merges write every new value as it is
held before it is signed, so that their callers give values as before. Section 2 lists the written forms the inventory
found. The examples run unchanged; in the new run (`csharp-80e4ccc`) the elements of revision 13 name no context and the
keys of revision 15 are in their order. `NewValueTests` of WWCP_POI shows seven values written otherwise refused when
applied and written as held when prepared, and custom data held as given.

The TypeScript port applies a new value as it is given and refuses one it can tell is written otherwise without the types
of the values: a JSON-LD context outside custom data, identified elements and the lists of section 2 out of their order or
given twice, a timestamp not UTC to the millisecond (`tests/newValues.test.ts`); it compares old values as they are given.
Every other form it cannot tell ends in other `afterETags` than the change set names, unless a change set was made to
pass: a known limit. WWCPPOIConformanceTests holds both implementations to three of the forms this port tells, in the
same words (`new-value-context`, `new-value-keys-out-of-order`, `new-value-timestamp`). Custom data holds its values as given in C# since Styx `06b592d3` (finding 20).


## 11. ✅ Epoch 1 checkpoints name their epoch, the specification says they do not

`SPECIFICATION.md:1459`: "Every history begins in epoch 1, whose commits and checkpoints do not name it."
`WWCP_POI3/History/RoamingNetworkCheckpoint.cs:1119` always writes `"epoch"`, also 1 (checkpoints 0 to 6 of example A11),
and section 10.1 and the examples show `"epoch": 1`. A reader following section 11 calculates other checkpoint
identifications. Commits do follow section 11.

**Fixed** in `9280f0b` (SPECIFICATION.md sections 5.1, 10.1 and 11): the specification follows the code, as it did before
epochs came in (`db522b4` wrote the sentence; the draft before it said "every history is epoch 1, and checkpoints name
it"). Every checkpoint names its epoch, 1 as well, and one without it is refused; a commit names it from the second one
on, and one naming epoch 1, a second written form of another identification, is refused. Both implementations did so
already; tests in both read epoch 1 and refuse the other forms. No identification changes.


## 12. ✅ A change without `oldValue` is not checked at all

**Where:** `WWCP_POI3/RoamingNetwork/RoamingNetwork.ChangeSets.cs:636,787`, `RoamingNetwork.ElementChanges.cs:92`
(`applied.OldValue is JToken …`), `TryApplyTransparencySoftwareChange` and its twin for certificates, and the new
`TryApplyModelChange` (`RoamingNetwork.ModelChanges.cs`).

A change naming no `oldValue` is applied without comparing anything; `null` means "absent". The `beforeETags` pin the
version anyway, so applying is safe; rebasing and merging, which rely on old values, are not.

**Checked** again against `36bb176`: the code was safer than the review said. Every apply compares an old value that is
given; merges (section 5.3) compare the versions of the tips, not the old values of their change sets, and a server
commits a change set made for an older version on that version, as a tip to be merged (`FindVersionFor`); and
`TryRebase` refuses a change without old value, but an `Add` or `AddElement`, since `16ec05d` ("a rebase could silently
overwrite a concurrent change"), held by `RebaseTests`. What was missing is the rule: the specification did not say that
a change set without old values can not be rebased, so a rebase made elsewhere could overwrite a concurrent change
unnoticed.

**Fixed** in `1717ee2`, and in this port alike: section 4 says so ("Rebased", "Old values"), and a change set naming
`rebasedFrom` with a change, but an `Add` or `AddElement`, without `oldValue` is refused when it is read
(`RebasedFromError`; `checkRebasedFrom` here), so that a rebase is held to what `TryRebase` does wherever it was made.
One not rebased is read as before. `RebaseTests` and `tests/changeSet.test.ts` hold it, and the vector
`changeSet-rebased-without-old-value` of WWCPPOIConformanceTests holds both implementations to it, refused in the same
words; and histories it signs itself, to old values compared as canonical JSON, `150000.0` refused for `150000`, and
to rebases with them and without (`old-value-*`, `rebased-*`).


## 13. ✅ The roaming network operator can not sign in place of a body or grid operator without keys

**Where:** `WWCP_POI3/RoamingNetwork/RoamingNetwork.Ownership.cs:903-907` (`SignerOf`: the RNO's signing keys for a party
without signing keys), `:680-686` (only keys that `MaySign(POIKeyUsages.Of(change))` count), `POIKeyUsages.cs`
(`TransparencySoftwareCertificate` → `certificates`, grid connection points → `infrastructure`, and new, models →
`models`); `docs/ConformityAssessmentBody.md`, `SPECIFICATION.md` section 4.1 ("the RNO for a body without signing keys").

A conformity assessment body or a grid operator may take no part, without keys; "then the RNO adds, changes and removes
its certificates in its place". `SignerOf` makes the RNO the owner, but its signing keys are counted only where they may
sign the usage of the change: `certificates` for a certificate, `infrastructure` for a grid connection point. The signing
keys of an RNO name `party` (examples A1 and A11 certify them so; section 4.1 gives the RNO `party` for everything it
owns), so they never may, and its identity keys are not asked.

**Demonstrated** again at `801bbce` (the last block of `MakeProofs.cs.txt`, run against the history of the examples whose
data the tests keep): a certificate of the BSI of example A13, which has no keys, signed by the quorum of `OCC`:

```
A certificate of the BSI, signed by the signing keys of AlphaOrg and BetaOrg of OCC: Refused, Change 0: Add of the TransparencySoftwareCertificate 'BSI-2026-0001' needs signatures by signing keys of 2 holders of the roaming network operator 'OCC' that may sign 'certificates'!
A certificate of the BSI, signed by the identity keys of AlphaOrg and BetaOrg of OCC: Refused, Change 0: Add of the TransparencySoftwareCertificate 'BSI-2026-0001' needs signatures by signing keys of 2 holders of the roaming network operator 'OCC'!
```

So the BSI can get no certificate until it has keys, unless the RNO certifies a signing key that names `certificates`
(and `infrastructure` for grid operators), which the specification does not tell it to. Since `801bbce` the same holds
for the models of a charging station or energy meter manufacturer without signing keys (`models`): a manufacturer is now
added with keys, but one that a roaming network names from before, without keys, gets no model stated in its place.

**Fix:** where the RNO signs in place of a party, count its signing keys that may sign `party`, the usage of everything
the RNO owns; or say in section 4.1 which usages the RNO's keys need for it. The TypeScript port does as the C#
implementation (`checkOwnership`).

**Demonstrated** again against `850440a` and **fixed** in `36bb176`, and in this port alike: a signing key of the RNO
counts for what it signs when it may sign the usage of what it changes, or `party`, the usage of everything it owns, so
also in place of a party without signing keys (`UsagesOf`, `MaySign` in `RoamingNetwork.Ownership.cs`: for counting the
holders of a quorum, for what a missing signature names, and for withdrawals). Nothing taken before is refused now: a
key the RNO certifies for `certificates` alone still signs the certificates of a body without keys; one certified for
`party`, as the examples certify them, does as well, and neither one certified for other usages only. Its identity keys
stay what they are, for keys only. Section 4.1 says so, and `docs/ConformityAssessmentBody.md` and
`docs/GridOperator.md`. `TransparencyTests` holds it in C#, with the RNO's signing key certified for `party`,
`certificates` and `infrastructure` alone; `tests/ownership.test.ts` in this port, signing with the Ed25519 keys of
section 6, whose private seeds the specification gives (`rnoHolders` of `checkOwnership` counts `party` besides the
usage). WWCPPOIConformanceTests holds both implementations to it for the certificates of a body without keys, its
signing keys certified for the party, for certificates and for tariffs alone (`rno-states-certificate*`), and WWCP_POI
for the grid connection points of a grid operator without keys.


## 14. ✅ The first checkpoint of a later epoch takes signatures of any algorithm

**Where:** `WWCP_POI3/History/RoamingNetworkHistory.Epochs.cs:389-394` (`CheckpointSignatureAlgorithmError`),
`SPECIFICATION.md` section 11.3.

Section 11.3: the first checkpoint of an epoch "is signed with the algorithms of both epochs …. Its signatures are
accepted with the algorithms of either epoch". The code accepts every algorithm for it, without asking the profiles of
either epoch. Harmless while the epoch before is epoch 1, which accepts every algorithm; from epoch 3 on, the first
checkpoint takes signatures of algorithms neither epoch 2 nor 3 accepts, e.g. after epoch 2 dropped ECDSA as weak.

**Fix:** keep the profiles of the epoch before (they are in its final checkpoint) and accept the algorithms of either.
The TypeScript port accepts every algorithm for it as well, as it knows the profiles of the epoch before only from that
checkpoint.

**Fixed** in `65e658d`, and in this port alike: a history knows the profiles of the epoch before
(`PreviousEpochProfiles`, `History.previousEpochProfiles`): those of the first epoch are the default ones; a history
started by `TryStartNextEpoch` (`startNextEpoch`) knows those of the epoch it closed, and a snapshot of an epoch after
the second names them in its `epoch`, `{epoch, profiles, previous?, previousProfiles?}`, which `ToSnapshotJSON` and the
store write. The first checkpoint of an epoch takes a signature, and `TryMakeCheckpoint` and `TryCloseEpoch` a signer, of
the algorithms of either epoch alone; without the profiles of the epoch before, of its own alone (SPECIFICATION.md 11.3).
`EpochTests` holds it through three epochs, ES256 and ML-DSA-65 in the second, ML-DSA-65 alone in the third, Ed25519
refused; `tests/epochAlgorithms.test.ts` in this port, with checkpoints made after the epoch 2 of QA; and
WWCPPOIConformanceTests both, through three epochs of a history it signs itself (`epoch-*`).


## 15. ✅ Who stated a certificate can not be told once its body has keys

**Where:** `docs/ConformityAssessmentBody.md` ("A reader tells them apart: a body without keys signed none of its
certificates"), example A13 (*Limits*), `RoamingNetworkEffectiveTree.cs` (the proof gives the skeleton of the body).

A certificate of a body without keys is a statement of the RNO; one the body adds with its keys is its own. Once the RNO
gives the body keys, both kinds look the same: a station proof gives the certificate and the body with its current keys,
and an app reading "the body has keys" concludes it stated the certificate. Which key signed it, only the commit that
added it tells, and the app does not have it.

**Fix:** let the certificate name who stated it (e.g. `statedBy`), or keep the signature of its change in it, so that the
proof carries it. The TypeScript port reports what the proof shows, `bodyHasKeys`, and says so.

**Fixed** in `65e658d`, and in this port alike: a certificate the RNO adds or changes in place of a body without
signing keys says so, `"statedBy": "roamingNetworkOperator"` (`StatedByRoamingNetworkOperator`); one the body signs names
none. A change set adding or changing a certificate whose `statedBy` does not say who signs it, as the version before has
the keys of the body, is refused; a body that got its keys since changes a certificate the RNO stated only by removing its
`statedBy`, stating it itself (SPECIFICATION.md 4.1). The proof gives it with the certificate. `TransparencyTests` holds
it; this port refuses such change sets alike (`tests/certificateStatedBy.test.ts`) and gives every certificate of a
verified station with `statedBy`, `ConformityAssessmentBody` or `RoamingNetworkOperator`, in place of `bodyHasKeys`.
No example states a certificate in place of a body; WWCPPOIConformanceTests holds both implementations to it with a
history it signs itself (`rno-states-certificate-unsaid`, `body-*`).


## 16. ✅ A certificate is for a version of a model, but no station or meter names one of its model's

**Where:** `WWCP_POI3/RoamingNetwork/ChargingStationManufacturer/ChargingStationModel/ChargingStationModel.cs:160` and
`WWCP_POI3/RoamingNetwork/EnergyMeterManufacturer/EnergyMeterModel/EnergyMeterModel.cs:166` (`Versions`, one list),
`WWCP_POI3/RoamingNetwork/ChargingStationManufacturer/ChargingStation/ChargingStation.cs:249,254` (a station names
`manufacturerId` and `modelId`, no version; its template neither), `WWCP_POI3/RoamingNetwork/EnergyMeterManufacturer/EnergyMeter/EnergyMeter.cs:173,178`
and `.../EnergyMeter/Template/EnergyMeterTemplate.cs:174,179` (`HardwareVersion`, `FirmwareVersion`, texts),
`WWCP_POI2/RoamingNetwork/TransparencySoftware/TransparencySoftwareCertificate.cs:154` (`ChargingStationModelVersion`,
mandatory), `docs/ChargingStationManufacturer.md` (`versions`: "e.g. hardware revisions … A certificate names one of
them"), `docs/EnergyMeterManufacturer.md` (`versions`: "e.g. hardware or firmware versions"),
`examples/csharp/exampleA2.cs:213-246` (the models and their versions), `examples/csharp/exampleA13.cs:244-248`.

A certificate is issued for a model in a hardware revision and a firmware version, both of the charging station and of
the energy meter: another revision or another firmware is not certified until the certificate names it. Since `801bbce`
WWCP_POI names models, and a certificate names a model, but the versions are not told apart, nor named where they
would be compared:

- **The model** has `versions`, one list of texts: "e.g. hardware revisions" for a model of charging stations, "e.g.
  hardware or firmware versions" for a model of energy meters. Whether a `1.0` is a revision of the hardware or a version
  of the firmware, nobody can tell; a model in two revisions and three firmware versions lists either six combinations
  or five versions that do not say which go together.
- **The station** names its manufacturer and model, but neither its hardware revision nor its firmware version, and
  neither does its template. **The meter** names `hardwareVersion` and `firmwareVersion`, as it should, but as texts
  the network checks against nothing, not against the `versions` of its model either.
- **The certificate** names one `chargingStationModelVersion`, checked to be one of the `versions` of the model: one
  text for hardware and firmware alike, and one only, although a certificate covers a revision with the firmware
  versions it was extended to. There is no certificate of a meter model (17).

So an app can tell that the certificate is for the model of the station and for *a* version of it, not for the
hardware and firmware the station is. Example A13 shows it: the GD-DC300 has the versions 1.0 and 1.1, the certificate
of the PTB is for 1.0, and the app prints "the model the certificate is for, in one of its versions", for a station
that may be a 1.1, which nobody certified, running a firmware nobody names. Whatever the version stands for, the claim
the app shows is wider than the certificate.

**Fix:** tell hardware and firmware apart, in the model, in what is of the model, and in the certificate.

- **The model** of a charging station or an energy meter names its `hardwareRevisions` and its `firmwareVersions`, two
  lists in place of `versions`.
- **The station** and its template name their `hardwareRevision` and `firmwareVersion`, as **the meter** and its
  template do already, there as `hardwareVersion`, to be named `hardwareRevision` as well; each is checked against the
  lists of its model, a reference error otherwise. A firmware update is a change of the station or meter its operator
  signs, so that the history tells which firmware measured when.
- **The certificate** of a station model, and that of a meter model (17), names the hardware revisions and the firmware
  versions it covers, each one of its model's; an amendment adds firmware versions to it.
- An app compares the hardware revision and the firmware version of the station with the certificate of the station,
  those of each meter with the certificate of the meter.

The TypeScript port reports `forThisModel` as the C# example decides it (manufacturer, model, and a version of the
model) and says so.

**Fixed** in `7e0b0ac`, and in this port alike: a model of charging stations or energy meters names its
`hardwareRevisions` and `firmwareVersions` in place of `versions`; a charging station and its template name a
`hardwareRevision` and a `firmwareVersion`, an energy meter and its template as before, its `hardwareVersion` now
`hardwareRevision`, each one of its model and only with it, as the station or meter is at runtime (a template without a
model gives them to members of their own model); a certificate names the `hardwareRevisions` and `firmwareVersions` of
its model it covers, at least one of each, and refuses the `chargingStationModelVersion` of before. The references are
checked after every change set, so that a revision or firmware version still named stays in its model. Example A13
compares the hardware revision and the firmware version of the station with its certificate. This port applies the
changes of them and takes them of templates; the references, as those to manufacturers and models before, it leaves to
WWCP_POI. WWCPPOIConformanceTests holds both implementations to a station and a meter naming them, and WWCP_POI alone to
the references (`station-firmware-of-no-model`, `station-revision-not-certified`).


## 17. ✅ An energy meter names the certificate of a station model, and has none of its own

**Where:** `WWCP_POI2/RoamingNetwork/TransparencySoftware/TransparencySoftwareCertificate.cs:33-38,141-154` (a document
"for a charging station model/version", naming its manufacturer, model and version),
`WWCP_POI3/RoamingNetwork/TransparencySoftware/TransparencySoftwareAssignment.cs:32-42` (`certificateId` in the
`transparencySoftwareStatus` of an energy meter), `WWCP_POI3/RoamingNetwork/EnergyMeterManufacturer/EnergyMeter/EnergyMeter.cs:153,158`
(the meter names its manufacturer and model), `WWCP_POI3/RoamingNetwork/EnergyMeterManufacturer/EnergyMeterModel/EnergyMeterModel.cs`
(a model of energy meters, with `versions` and `accuracyClass`, no certificate), `WWCP_POI3/RoamingNetwork/RoamingNetwork.cs:2386-2405,2934-2948`
(`UnknownTransparencyReference`, the energy meters and their templates), `docs/ConformityAssessmentBody.md` ("Energy
meters name its certificates"), `examples/csharp/exampleA13.cs:239-249`.

A certificate is for a model of **charging stations** or a model of **energy meters**, each of its manufacturer: e.g.
the EU type examination certificate of an AC meter under the MID, or, in Germany, the type examination certificate of a
charging station as the measuring instrument it is, under the Mess- und Eichgesetz. It names the components it was
issued with. One is the **transparency software**: a product of its own, of its own manufacturer, as WWCP_POI has it
(a `TransparencySoftwareManufacturer` and its releases), which the certification of a station needs verified as that
of a meter does. Another, for a station, are the **energy meters** it mounts. WWCP_POI knows one certificate, the
`TransparencySoftwareCertificate`: named after one of its components, for a station model only
(`chargingStationManufacturerId`, `chargingStationModel`, `chargingStationModelVersion`), with the releases it verifies
or finds compatible as its only components, and named by the energy meters, in their `transparencySoftwareStatus`, not
by the station. So:

- The network checks that a certificate a meter names exists and covers the release the meter names, not that it is for
  the model of the station the meter is part of, although since `801bbce` both the station and the certificate name the
  model formally, with its manufacturer. A charging station operator can name, for the meters of an AC station, a
  certificate the body issued for a DC model, and the network takes it; only an app comparing the certificate with the
  station notices (example A13 does, the TypeScript port does with `forThisModel`).
- A meter of a charging pool or of a grid connection point, part of no station, names a certificate of a station model
  just as well.
- The certificate of the meter itself has no place: the meter names its model, but no body can state a certificate for
  a model of meters, with the transparency software it was verified with, and no app can show one. Nor can a
  certificate of a station name the meters it was issued with. The station names its certificate nowhere but in
  `certificationInfo`, a URL.

Checking only the reference, a certificate a meter names against the model of its station, would write the confusion
down: the `certificateId` of a meter would be the certificate of its station for good, and the certificate of the meter
would still have no place.

**Fix:** one kind of certificate, for a model of charging stations or of energy meters, naming its components.

- **The certificate**, e.g. `Certificate` in the `certificates` of the body issuing it, in place of the
  `TransparencySoftwareCertificate`, is for exactly one model, of charging stations or of energy meters, with its
  manufacturer, in the hardware revisions and firmware versions it covers (16). It names its components: the
  transparency software releases it verifies or finds compatible, for a station as for a meter, and, for a station, the
  models of the energy meters it was issued with, with their hardware revisions and firmware versions. Its legislation,
  number, URL and validity stay as they are.
- **The station and the meter** name their certificates, each with its template, e.g. `certificateIds`: a station
  certificates of a station model, a meter certificates of a meter model, each checked against their manufacturer,
  model, hardware revision and firmware version, a reference error otherwise. Where a certificate of a station names
  meters, every meter of the station is one of them, of its model, revision and firmware.
- **The transparency software status** of a meter names a release and its legal status, no certificate. A certificate
  of the meter or of its station naming the release among its components proves the status; an app finds it among
  them. A meter part of no station has its own certificates for it only.
- The proof of a charging station gives the certificates of the station and of its meters, with the skeletons of their
  bodies, so that an app shows each next to what it is for.

The TypeScript port reports, as example A13 does, whether the certificate a meter names is for the model of its station
(`forThisModel`), and keeps the certificate where WWCP_POI keeps it until WWCP_POI names it where it belongs.

**Fixed** in `987fa26`, and in this port alike: `ConformityCertificate` (the `certificates` of a body, context
`…/certificate/v1`; not `Certificate` in C#, a name of Styx and of WWCP_Core) is for exactly one model, of charging
stations or of energy meters, with its manufacturer, in the hardware revisions and firmware versions it covers, and names
its components: the releases it verifies or finds compatible, and of a charging station model the energy meters it was
issued with (`energyMeters`). A charging station, an energy meter and their templates name the certificates of their
models in `certificateIds`; WWCP_POI checks after every change set that each is of their kind, for their model, covering
their revision and firmware, and, where a certificate of a station names energy meters, that every meter of the station
is one of them. A `transparencySoftwareStatus` names a release and its legal status, no certificate, and refuses a
`certificateId`. The proof of a charging station gives the certificates the station and its meters name. In example A13
the PTB certifies the GD-DC300 with the KDM-500 and Chargy as its components, and the KDM-500 with Chargy. This port
gives the `certificates` of a verified station, each with `forThisModel`, and with the transparency software of a meter
the certificates naming its release; the references a version holds it leaves to WWCP_POI, as it does those of 16.
WWCPPOIConformanceTests holds WWCP_POI alone to them (`station-certificate-of-a-meter`, `meter-certificate-of-a-station`,
`meter-not-of-the-certificate`).


## 18. ✅ What one party names blocks what another party withdraws

**Where:** `WWCP_POI3/RoamingNetwork/RoamingNetwork.ChangeSets.cs:1137-1155` (the references checked after every change
set), `docs/ChargingStation.md` ("a manufacturer or a model can not be removed while a station names it"),
`SPECIFICATION.md:276-277` ("The RNO decides who is a member: removing a party removes everything it embeds, and needs no
signature of the party").

Since `801bbce` the manufacturers are parties, and the references to them are checked after every change set: a station
or template of a charging station operator naming a manufacturer or a model, a certificate of a body naming a model and
a version of it. So a manufacturer can not remove a model, or a version of it, as long as a station of an operator or a
certificate of a body names it, and the RNO can not remove a manufacturer as long as a station of another party names
it: the RNO decides who is a member only once the operators and bodies changed their data. Before, the same held for the
releases of transparency software manufacturers and the certificates of bodies the meters name. The documentation says
so for models; the specification's "removing a party removes everything it embeds" does not.

**Fix:** say in section 4.1 that a party can not be removed, nor anything withdrawn, while another party names it, and
who resolves it; or let a removal of the RNO remove or clear the references to what it removes.

**Fixed** in `52f1172`, the specification following the code: section 4.1 says that what another party names, a party,
a model, a hardware revision or firmware version, a release, a certificate, a grid connection point, a charging station
or a parking space, is not withdrawn while it names it, also not by the RNO; the party naming it changes first, or both
change it in one change set both sign, so that the RNO removes a party another one still names only together with that
party. A refusal for it says so: when the references a change set leaves were resolved by the version before it,
`TryApplyChangeSet` adds that the change set withdraws what is still named, and how it is withdrawn.
`ManufacturerModelTests` holds it. This port leaves the references a version holds to WWCP_POI, as it does those of 16
and 17. WWCPPOIConformanceTests holds both implementations to a withdrawal together with what names it
(`withdrawn-with-what-names-it`), and WWCP_POI alone to the refusal (`withdrawn-while-named-*`).


## 19. Smaller points

- ✅ **Trust anchor quorum (fixed in `3e32f48`):** `minConsensus` is checked against the number of keys, not of holders
  (`RoamingNetworkTrustAnchor.cs`, `TryCheck`); see 1. Since the trust anchor names its keys per holder, `TryCheck`
  checks `minConsensus` against the number of holders.
- ✅ **Certificates and statements of another operator in a proof (fixed in `65e658d`):** `RoamingNetworkProof.Verify`
  does not compare the `roamingNetworkOperatorId` of the certificates and of the key statement with the operator of the
  proof (the content check of a full version does). The TypeScript port does. Demonstrated by the vectors
  `trust-certificate-operator` and `trust-statement-operator` (D6) of WWCPPOIConformanceTests. `Verify` refuses a key
  statement of another operator, in the words of this port, and counts no attestation by a signing key certified for
  another one; `KeyStatementTests` holds both, each proof attested anew over what it gives. WWCPPOIConformanceTests no
  longer lists D6 as a deviation: the two vectors hold both implementations to it.
- ✅ **Checkpoint roles (no change of code needed):** required roles are checked as the role a signer declares;
  `examples/csharp/exampleA4.cs` accepts a signing key of the RNO in any role. The TypeScript port binds witness
  signatures to the key trusted for the witness named, and ignores, rather than refuses, signatures by keys it does not
  trust (so nobody blocks a checkpoint by adding one). Checked again: the verifiers of the examples bind each role to its
  keys, `ExampleA4.SigningKeyOf` takes signatures in the role `roamingNetworkOperator` alone, `ExampleA6` those of a
  witness by the key trusted for the witness it names; so the claim on example A4 does not hold. The delegates
  `VerifyCheckpointSignatureDelegate` and `VerifyCommitSignatureDelegate` say since `65e658d` that their key must
  be the one trusted for the role and the signer a signature names. That WWCP_POI refuses a checkpoint carrying a
  signature it does not trust, where this port ignores it, stays as it is.
- ✅ **Key statements trusted unchecked in the examples (fixed in `65e658d`):** `ExampleA4.SigningKeyOf`
  (`examples/csharp/exampleA4.cs:260-276`) trusts every identity key the key statement of the version it is given names,
  without verifying the statement against the trust anchor. Example A11 hands it the version of the snapshot of checkpoint 5, which nothing checked against the
  trust anchor (only the trusted witnesses protect the verifier there), example A12 the published `QA.json` (its
  *Limits* say so). The examples are what implementers copy: a verifier following the history should verify the key
  statement where it starts, and follow it by succession only through commits it checked. The TypeScript port does
  (`OperatorTrust.of`, `OperatorTrust.followedBy`). **Fixed** in `65e658d`: `ExampleA4.SigningKeyOf` trusts the
  identity keys a key statement names only once it verified the statement against the trust anchor it is given, and the
  witnesses of example A6 follow the key statement by succession, commit by commit (`ExampleA4.Followed`): so they follow
  the ML-DSA keys of epoch 2, which the old keys stated, and refuse a version whose statement the keys they trust did not
  sign. The examples run as before, but for the words of example A13 on who states a certificate (15).
- ✅ **Price statements taken along into an epoch they are not of (fixed in `1964903`):** `TryStartNextEpoch` takes the
  current statements of epoch 1, signed with ES256, into epoch 2, which a peer starting in epoch 2 refuses (example A12,
  *Limits*). Left open as a question of design, which example A12 calls open as well: whether a peer takes the statements
  taken along with the algorithms of the epoch before, as the signatures of the first checkpoint, or the epoch takes along
  only those of its own algorithms and the chains of the others begin anew. **Decided** and fixed in `1964903`, the
  latter: the next epoch takes along the current statements of its algorithms alone. The chain of an entity whose
  statement it does not take along goes on all the same: its next statement has the next `sequence` and names the last
  one of the epoch before as `previous`, which no server checks across the epochs, as none holds it as the current one
  there (SPECIFICATION.md 11.4). A server signing for an operator follows that one, also after a restart (`EpochTests`);
  the mirror of example A12 takes the price statements of `OCC` now.
- **Models describe, nothing compares (open):** a model states `maxPower`, `currentTypes`, `connectorTypes` and `numberOfEVSEs`
  (charging stations), `currentTypes`, `maxCurrent` and `signatureMethods` (energy meters); a station of 300 kW may name
  a model of 44 kW, a meter signing with a method its model does not name. The network checks only that the model
  exists. An app showing the model's data next to the station's may show both, contradicting each other. Left open as a
  question of design: whether the data of a model is a limit for what names it, or a description beside it.
- ✅ **Keyless parties in section 4.1 (fixed in `65e658d`):** `SPECIFICATION.md:276` says a party is added with
  keys of each kind, "a grid operator also with none"; the code (`TryCheckPartyChange`) and the rest of section 4.1 allow
  a conformity assessment body without keys as well. Section 4.1 says so now.
- ✅ **Building the examples (fixed in `65e658d`):** `examples/csharp/examples.csproj` references `Hermod`, `Styx`,
  `WWCP_Node` as sibling checkouts, and `WWCP_Node` needs `Norn` and `Urdr` as well, at the commits the RoamingHubCLI
  pins; `examples/README.md` says only `dotnet run`. On Windows, a checkout below a long path needs
  `git config core.longpaths true`. Example A12 opens two servers on `127.0.0.1`. `examples/README.md` says all of it
  now.
- ✅ **Dependencies of COSE.TS (resolved):** `@vanaheimr/cose@0.9.0` depended on `@vanaheimr/metrological-cbor@^0.10.0`,
  this library on `^0.11.0`: a consumer got two copies of the CBOR codec. `@vanaheimr/cose@0.10.0` depends on
  `^0.11.1`, and this library takes both at `^0.10.0` and `^0.11.1`: one copy.


## 20. ✅ Custom data: numbers as binary floating-point numbers, timestamps in the time zone of the server

**Where:** Styx `Illias/CustomData/ACustomDataNew.cs:135-139` (`ToJObject`: `JObject.Parse` with the defaults of
Newtonsoft.Json), `CustomDataNew.cs:290-291`, `CustomDataValue.cs:349-366`; written by `POIEntityMetadata.cs:97-98`.

`customData` is read through System.Text.Json and written back through `JObject.Parse`: a non-integral number becomes a
`double` (`1.50` → `1.5`, digits beyond a double lost), and a text that looks like a timestamp becomes a .NET
`DateTime`, written in the round-trip format (`"2024-01-01T12:00:00Z"` → `"2024-01-01T12:00:00.0000000Z"`); one with an
offset is converted into the local time zone of the server. Two servers in different time zones then hold the same
change otherwise: other `afterETags`, and one of them refuses the change set. Found by the inventory of finding 10
(confirmed by reading; the defaults of Newtonsoft.Json inferred). Since finding 10, a value written so is refused, or
written as held by `CreateChangeSet` - in the time zone of the server that prepares it. SPECIFICATION.md section 7 says
so.

**Fix:** read and write custom data as JSON, without converting numbers or texts (`DateParseHandling.None`,
`FloatParseHandling.Decimal`, or the JSON text kept as it is).

**Fixed** in Styx `06b592d3`: `ToJObject()` builds the JSON object of custom data from its values, and `ParseJObject()`
reads the values of the JSON object it is given, no longer each through a JSON text read again. A text stays a text, also
one that looks like a timestamp, in every time zone; a number with a fraction stays a decimal with its decimal places
where the decimal writes it as given (`1.50`), any other number its JSON text (`1e-30`, `1.5e2`, an integer beyond 64
bits). SPECIFICATION.md of WWCP_POI says so in section 2 since `7493da7` and no longer lists it as an open point in section 7;
`NewValueTests.Custom_data_is_held_as_given` prepares and applies `1.50`, `0.1` and timestamps with `Z` and an offset,
which before the fix ended in an `InvalidCastException`. The examples and the frozen run hold no custom data: no
document of them changes.

The vectors hold both implementations to it: `spec-2-custom-data-decimals`, `-integers`, `-texts` and `-nested` of
`poi-specification.json` give the content of the example of section 6 with custom data, its canonical JSON and its
ETags. Against Styx `91901a9`, WWCP_POI wrote `0.1000000000000000055511151231` as `0.1`, `1.50` as `1.5`, an integer of
39 digits as `1.2345678901234568E+38`, `"2026-10-26T07:00:00-05:00"` as `"2026-10-26T13:00:00.0000000+01:00"` in the
time zone of the machine, and its CBOR ETag of a text that looks like a timestamp ended in the `InvalidCastException`;
against `06b592d3` it calculates what this port does.


## 21. ✅ The custom data of an address is lost

**Where:** Styx `Illias/Helpers/Address.cs:403,424,533-535`.

An address reads its custom data from `"CustomData"` and writes it as `"customData"`: given in lower case it is dropped,
given as `"CustomData"` it is written in lower case and dropped when read again. Found by the inventory of finding 10
(confirmed by reading). Since finding 10, an address giving custom data is refused, as the content does not hold it.

**Fix:** read `"customData"`.

**Fixed** in Styx `06b592d3`: an address reads `"customData"`, its values as finding 20 reads them, and
`Address.TryParse(String)` reads its JSON text without turning texts into timestamps or numbers into doubles. The
address of a charging station keeps its custom data in `NewValueTests.Custom_data_is_held_as_given`.

The vector `spec-2-custom-data-address` holds both implementations to it: the address of the charging station operator
of section 6 with custom data. Against Styx `91901a9`, WWCP_POI wrote the address without it.


## What was checked and found sound

Canonical JSON and deterministic CBOR (all Styx vectors), ETags, commit and checkpoint identifications with SHA-256 and
SHA-512, the effective tree with templates, tariffs, energy meter templates, charging station and energy meter
manufacturers with their models, transparency software manufacturers and conformity assessment bodies, RFC 9162 trees and
audit paths (bounds, domain separation) with SHA-256 and SHA-512, key thumbprints and their checks, the signature inputs
of key statements, certificates, commits, checkpoints, attestations, change sets and price statements (ES256/384/512,
Ed25519, Ed448, ML-DSA-65/87), Base64 canonicality, the trust anchor (QR code, URL), the ownership of every change of both
epochs of the examples (the quorum of the RNO, the proof of possession of new identity keys, the keys of the
manufacturers for their models, of the new parties for their releases and certificates), checkpoint lines, the final
checkpoint of epoch 1 and the genesis of epoch 2, archive segments, price statement trees and proofs, the evidence of
example A10, the pushed commit of example A12 and the station proofs of example A13 and of the proofs made for the tests,
with the models of the station and its meters, the others pruned: the TypeScript port, written from the specification
and the code, calculates all of them byte for byte as the C# implementation does, for the published data of two runs of
the examples at `801bbce`.
