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
| `poi-specification.json` | SPECIFICATION.md section 6, every value verbatim | `contents` (content, ETags), `skeletons` (skeleton, digest), `commits` (commit, content, identification), `keys` (COSE key, thumbprint), `signatures` (input, value, key, private seed) and `invalidSignatures`, `priceStatements` (statement, digest), `trustAnchors` (JSON, QR code). |
| `poi-trust.json` | SPECIFICATION.md sections 8.4 to 8.6 | `stationProofs`: proofs of the example network of section 6, its operator holding the quorum of section 6, signed with its Ed25519 keys: trust anchor and proof (JSON text), the time `at`, the `root` the proof leads to, and `expected` `accepted` or `refused`. |
| `poi-history.json` | `runs/csharp-dbf39b0`, the frozen run | Documents of the run and what an implementation must calculate of them: `versions` (ETags), `commits`, `checkpoints` (identifications and fields), `checkpointProofs`, `priceStatements` (digests, chains), `trustAnchors`, `stationProofs` (root, verified against the trust anchor at `at`), `replays` (the history commit by commit). |
| `poi-refusals.json` | the frozen run; SPECIFICATION.md | `vectors`: a document of the run with a JSON patch applied, checked at another time, against another trust anchor or checkpoint, or a text: each must be refused. |

## The frozen run

`runs/csharp-dbf39b0/` is what one run of the C# examples A1 to A13 of WWCP_POI at commit `dbf39b0` published (public
data only; its console output is `csharp-output.log`), and in `proofs/`, what `proofs/MakeProofs.cs.txt` made of the
same history with the C# implementation, at `at`. It replaces `csharp-801bbce`, which came from WWCP_POI.TS, since
`dbf39b0` changed the digests of price statements. WWCP_POI.TS keeps a vendored copy of it and of the `poi-*.json` for
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

## Adding vectors

Add them to the generator, with a fresh `id`, run it, and make sure both harnesses run them (or mark `requires` /
`notApplicable` deliberately). A vector enters only when at least two implementations agree on it - the generator's
anchors and one harness, at the least - or carries the `knownDeviations` of the one that does not.
