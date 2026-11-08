#!/usr/bin/env node
/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCPPOIConformanceTests <https://github.com/OpenChargingCloud/WWCPPOIConformanceTests>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Generates the golden test vectors of WWCP POI 3 (test-vectors/poi-*.json) from their sources:
 *
 *   - libs/Styx/Styx/Illias/JSON/README.md, section 4, and the escaping table of
 *     libs/Styx/StyxTests/Illias/JSON/CanonicalEncodingVectorsTests.cs: canonical JSON and deterministic CBOR;
 *   - libs/WWCP_POI/SPECIFICATION.md, sections 1 and 6: the examples of the specification, and section 2: custom data;
 *   - test-vectors/runs/<run>/: what one run of the C# examples A1 to A15 of WWCP_POI published, frozen;
 *   - test-vectors/runs/chargy-<commit>/: the fixtures of ChargyWebApp of the verifier extensions of WWCP_POI.TS 0.2.0,
 *     frozen; libs/WWCP_POI/WWCP_POI3/Verifier for their inputs (section 9);
 *   - and what it makes and signs itself, deterministically: the station proofs of section 4 (poi-trust.json) and the
 *     histories of section 7 (poi-histories.json), with the keys of section 6 of the specification and of seeds of its own.
 *
 * Every value is taken VERBATIM from its source, and this script refuses to write when a source no longer says it
 * (drift guard). Before writing anything it re-derives the anchors with nothing but node:crypto - the SHA-256 and
 * SHA-512 identifications, ETags of canonical JSON, tree digests, key thumbprints and Ed25519 signatures of section 6,
 * the digests that chain the price statements of the run; for what it signs itself the ETags of canonical JSON and
 * deterministic CBOR of every version of the run, the identifications of its commits, change sets and checkpoints, the
 * inputs of its signatures, and ES256 after RFC 6979 - and refuses to write when even one mismatches: an independent
 * third look, next to the two harnesses, at what the vectors claim.
 *
 *   node tools/generate-test-vectors.mjs                  writes test-vectors/poi-*.json
 *   node tools/generate-test-vectors.mjs --check          fails when the committed files differ (the CI drift guard)
 *   node tools/generate-test-vectors.mjs --mirror <dir>   also refreshes a vendored copy, e.g. libs/WWCP_POI.TS/tests/vectors
 *
 * Never edit the JSON files by hand: edit this script and run it again.
 */

import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify, X509Certificate } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';


const ROOT         = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT          = join(ROOT, 'test-vectors');
const RUN          = 'csharp-045e180';
const RUN_DIR      = join(OUT, 'runs', RUN);

/** A point in time while the key statements, the keys and the attestations of the frozen run are valid. */
const AT           = '2026-11-05T19:46:00.000Z';

const STYX_README  = 'libs/Styx/Styx/Illias/JSON/README.md';
const STYX_TESTS   = 'libs/Styx/StyxTests/Illias/JSON/CanonicalEncodingVectorsTests.cs';
const SPEC         = 'libs/WWCP_POI/SPECIFICATION.md';

/** How the two implementations under test are named in `knownDeviations`, `notApplicable` and `requires`. */
const CSHARP       = 'wwcp-poi3';
const TYPESCRIPT   = 'wwcp-poi.ts';

/**
 * The known deviations, by the anchor of their section in docs/implementation-deviations.md. A vector naming one is
 * held, for the implementation that deviates, to its deviation: the day it is fixed, that harness turns red, and the
 * marker is removed here.
 */
const DEVIATIONS = {
};

const deviation = (name) => {
    const { implementations, anchor } = DEVIATIONS[name] ?? fail(`no deviation ${name}`);
    return { knownDeviations: implementations, deviation: `docs/implementation-deviations.md#${anchor}` };
};

const args         = process.argv.slice(2);
const checkOnly    = args.includes('--check');
const mirrors      = args.flatMap((arg, index) => arg === '--mirror' ? [ args[index + 1] ] : []);

if (mirrors.some(mirror => mirror === undefined))
    fail('--mirror needs a directory');


// ---------------------------------------------------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------------------------------------------------

function fail(message) {
    console.error(`generate-test-vectors: ${message}`);
    process.exit(1);
}

const source = (file) => {
    const path = join(ROOT, file);
    if (!existsSync(path))
        fail(`the source ${file} is missing - run 'git submodule update --init' first`);
    return readFileSync(path, 'utf8').replaceAll('\r\n', '\n');
};

/** The drift guard: every value a vector takes from a source must still be written there, as it is. */
function quoted(file, text, what) {
    if (!source(file).includes(text))
        fail(`${file} no longer says ${what}: ${text.length > 120 ? text.slice(0, 117) + '...' : text}`);
    return text;
}

/** The EV Taler merchant of the example of ChargingStationOperator.md, as it gives it (sections 6 and 7). */
const EV_TALER_DOC = 'libs/WWCP_POI/docs/ChargingStationOperator.md';
const evTalerOfTheExample = () =>
    JSON.parse(`{${source(EV_TALER_DOC).match(/```json\n("evTaler": \{[\s\S]*?\n\})\n```/)?.[1] ?? fail(`${EV_TALER_DOC} no longer gives an example of an EV Taler merchant`)}}`).evTaler;

/** An object without the given properties. */
const without = (object, ...properties) => Object.fromEntries(Object.entries(object).filter(([ property ]) => !properties.includes(property)));

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha512 = (bytes) => createHash('sha512').update(bytes).digest('hex');
const utf8   = (text)  => Buffer.from(text, 'utf8');

function anchor(what, actual, expected) {
    if (actual !== expected)
        fail(`anchor mismatch, ${what}: calculated ${actual}, the source says ${expected}`);
}

/** An Ed25519 private key of a 32 byte seed (PKCS #8 of RFC 8410), its raw public key, and deterministic signatures. */
function ed25519(seedHex) {
    const key     = createPrivateKey({ key: Buffer.concat([ Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex') ]), format: 'der', type: 'pkcs8' });
    const spki    = createPublicKey(key).export({ format: 'der', type: 'spki' });
    return {
        publicKey:  spki.subarray(12).toString('base64'),
        sign:       (text) => sign(null, utf8(text), key).toString('base64'),
    };
}

/** The COSE key (RFC 9052, OKP, Ed25519) of a raw public key, in deterministic CBOR: {1: 1, -1: 6, -2: x}. */
const coseKeyOf = (publicKeyBase64) => Buffer.concat([ Buffer.from('a301012006215820', 'hex'), Buffer.from(publicKeyBase64, 'base64') ]).toString('base64');

function ed25519Verify(publicKeyBase64, text, valueBase64) {
    const key = createPublicKey({ key: Buffer.concat([ Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKeyBase64, 'base64') ]), format: 'der', type: 'spki' });
    return verify(null, utf8(text), key, Buffer.from(valueBase64, 'base64'));
}

/** An Ed448 private key of a 57 byte seed (PKCS #8 of RFC 8410), its COSE key (OKP, crv 7) and deterministic signatures. */
function ed448(seedHex) {
    const key     = createPrivateKey({ key: Buffer.concat([ Buffer.from('3047020100300506032b6571043b0439', 'hex'), Buffer.from(seedHex, 'hex') ]), format: 'der', type: 'pkcs8' });
    const raw     = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(12);
    return {
        coseKey:    Buffer.concat([ Buffer.from('a301012007215839', 'hex'), raw ]).toString('base64'),
        sign:       (text) => sign(null, utf8(text), key).toString('base64'),
    };
}


// ---- ECDSA on P-256 with the nonces of RFC 6979, as Styx signs ES256: deterministic as Ed25519 is -------------------

const P256 = {
    p:  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    n:  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    G:  [ 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n ],
};

const modulo    = (a, m) => ((a % m) + m) % m;
const bytesOf   = (value, length) => Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex');
const bigintOf  = (bytes) => BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));

function inverse(a, m) {
    let [ result, base, exponent ] = [ 1n, modulo(a, m), m - 2n ];
    for (; exponent > 0n; exponent >>= 1n, base = base * base % m)
        if (exponent & 1n) result = result * base % m;
    return result;
}

/** The sum of two points of P-256 (null: the point at infinity), its a being -3. */
function p256Add(P, Q) {
    if (P === null) return Q;
    if (Q === null) return P;
    const { p } = P256;
    if (P[0] === Q[0] && modulo(P[1] + Q[1], p) === 0n)
        return null;
    const lambda = P[0] === Q[0] ? modulo(3n * P[0] * P[0] - 3n, p) * inverse(2n * P[1], p) % p
                                 : modulo(Q[1] - P[1], p) * inverse(Q[0] - P[0], p) % p;
    const x      = modulo(lambda * lambda - P[0] - Q[0], p);
    return [ x, modulo(lambda * (P[0] - x) - P[1], p) ];
}

const p256Times = (k, P = P256.G) => [ ...k.toString(2) ].reduce((sum, bit) => bit === '1' ? p256Add(p256Add(sum, sum), P) : p256Add(sum, sum), null);

/** The nonce of RFC 6979, section 3.2, for P-256 and SHA-256, of a private key and the hash of a message. */
function rfc6979(d, hash) {
    const { n }  = P256;
    const hmac   = (key, ...data) => createHmac('sha256', key).update(Buffer.concat(data)).digest();
    const x      = bytesOf(d, 32);
    const h1     = bytesOf(modulo(bigintOf(hash), n), 32);
    let   V      = Buffer.alloc(32, 1);
    let   K      = hmac(Buffer.alloc(32, 0), V, Buffer.of(0), x, h1);
    V = hmac(K, V);
    K = hmac(K, V, Buffer.of(1), x, h1);
    V = hmac(K, V);
    for (;;) {
        V = hmac(K, V);
        const k = bigintOf(V);
        if (k >= 1n && k < n)
            return k;
        K = hmac(K, V, Buffer.of(0));
        V = hmac(K, V);
    }
}

/** An ES256 key of a private scalar: its COSE key (EC2, crv 1) and signatures r || s with the nonces of RFC 6979. */
function es256Of(d) {
    const { n }   = P256;
    const [ x, y ] = p256Times(d);
    return {
        coseKey:    Buffer.concat([ Buffer.from('a401022001215820', 'hex'), bytesOf(x, 32), Buffer.from('225820', 'hex'), bytesOf(y, 32) ]).toString('base64'),
        sign:       (text) => {
            const hash = createHash('sha256').update(utf8(text)).digest();
            const k    = rfc6979(d, hash);
            const r    = modulo(p256Times(k)[0], n);
            const s    = modulo(inverse(k, n) * (bigintOf(hash) + r * d), n);
            if (r === 0n || s === 0n)
                fail('ES256: a nonce of RFC 6979 that signs nothing');
            return Buffer.concat([ bytesOf(r, 32), bytesOf(s, 32) ]).toString('base64');
        },
    };
}

/** An ES256 key of a 32 byte seed, its scalar in [1, n - 1]. */
const es256 = (seedHex) => es256Of(modulo(bigintOf(Buffer.from(seedHex, 'hex')), P256.n - 1n) + 1n);


// ---- Verifying with a COSE key (RFC 9052): EC2 of P-256, P-384 and P-521, OKP of Ed25519 and Ed448, AKP of ML-DSA ----

/**
 * The SubjectPublicKeyInfo (RFC 9881) of an ML-DSA public key: the DER head of each parameter set, its OID
 * 2.16.840.1.101.3.4.3.17 to 19, and the key as its BIT STRING, by its COSE algorithm (-48 to -50).
 */
const ML_DSA_SPKI = {
    [-48]: '30820532300b06096086480165030403110382052100',
    [-49]: '308207b2300b0609608648016503040312038207a100',
    [-50]: '30820a32300b060960864801650304031303820a2100',
};

/** The public key of a COSE key in Base64 for node:crypto, or undefined for a kind node:crypto does not verify here. */
function nodeKeyOf(coseKey) {
    const map   = decodeCbor(Buffer.from(coseKey, 'base64'));
    const url   = (bytes) => Buffer.from(bytes).toString('base64url');
    if (map[1] === 7)
        return ML_DSA_SPKI[map[3]] === undefined ? undefined : createPublicKey({ key: Buffer.concat([ Buffer.from(ML_DSA_SPKI[map[3]], 'hex'), map[-1] ]), format: 'der', type: 'spki' });
    const jwk   = map[1] === 2 ? { kty: 'EC',  crv: { 1: 'P-256', 2: 'P-384', 3: 'P-521' }[map[-1]], x: url(map[-2]), y: url(map[-3]) }
                : map[1] === 1 ? { kty: 'OKP', crv: { 6: 'Ed25519', 7: 'Ed448' }[map[-1]],           x: url(map[-2]) }
                :                undefined;
    return jwk === undefined || jwk.crv === undefined ? undefined : createPublicKey({ key: jwk, format: 'jwk' });
}

/** Whether a signature value verifies with a COSE key, or undefined where node:crypto does not verify its algorithm. */
function verifiesWith(algorithm, coseKey, text, valueBase64) {
    const key   = nodeKeyOf(coseKey);
    const hash  = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' }[algorithm];
    if (key === undefined || (hash === undefined && ![ 'Ed25519', 'Ed448', 'EdDSA', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87' ].includes(algorithm)))
        return undefined;
    return hash === undefined ? verify(null, utf8(text), key, Buffer.from(valueBase64, 'base64'))
                              : verify(hash, utf8(text), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(valueBase64, 'base64'));
}


// ---- Base45 (RFC 9285) and the CBOR this script needs to read: trust anchors, COSE keys -----------------------------

const BASE45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

function fromBase45(text) {
    const bytes = [];
    for (let i = 0; i < text.length; i += 3) {
        const chunk  = [ ...text.slice(i, i + 3) ].map(c => { const v = BASE45.indexOf(c); if (v < 0) fail(`no Base45: ${c}`); return v; });
        const value  = chunk.reduce((sum, digit, index) => sum + digit * 45 ** index, 0);
        if (chunk.length === 3) bytes.push(value >> 8, value & 0xff);
        else                    bytes.push(value);
    }
    return Buffer.from(bytes);
}

function decodeCbor(bytes) {
    let offset = 0;
    const read = () => {
        const initial = bytes[offset++], major = initial >> 5, info = initial & 0x1f;
        let length = info;
        if      (info === 24) length = bytes[offset++];
        else if (info === 25) { length = bytes.readUInt16BE(offset); offset += 2; }
        else if (info === 26) { length = bytes.readUInt32BE(offset); offset += 4; }
        else if (info  >  26) fail('CBOR of a trust anchor or a COSE key: no 64 bit lengths or indefinite lengths expected');
        switch (major) {
            case 0: return length;
            case 1: return -1 - length;
            case 2: { const value = bytes.subarray(offset, offset + length); offset += length; return value; }
            case 3: { const value = bytes.subarray(offset, offset + length).toString('utf8'); offset += length; return value; }
            case 4: return Array.from({ length }, read);
            case 5: { const map = {}; for (let i = 0; i < length; i++) { const key = read(); map[key] = read(); } return map; }
            default: fail(`CBOR of a trust anchor or a COSE key: major type ${major} not expected`);
        }
    };
    const value = read();
    if (offset !== bytes.length)
        fail('CBOR of a trust anchor or a COSE key: bytes after the data item');
    return value;
}


// ---- Canonical JSON, as far as the anchors need it --------------------------------------------------------------------
//
// Numbers stay the text they are written as (JSON.parse with the source text of its values): the C# implementation
// writes them canonically already. Strings are written as Styx writes them for what the frozen run holds; anything this
// script does not know how Styx writes it is refused, never guessed.

const RAW = Symbol('raw number');

const parseRaw = (text) => JSON.parse(text, (_key, value, context) => typeof value === 'number' ? { [RAW]: context.source } : value);

/** A number as JavaScript holds it, of one read with parseRaw() or given as one. */
const numberOf = (value) => value?.[RAW] !== undefined ? Number(value[RAW]) : value;

function canonicalString(text) {
    let result = '"';
    for (const char of text) {
        const code = char.codePointAt(0);
        if      (char === '"')    result += '\\"';
        else if (char === '\\')   result += '\\\\';
        else if (char === '\n')   result += '\\n';
        else if (char === '\r')   result += '\\r';
        else if (char === '\t')   result += '\\t';
        else if (code >= 0x20 && code < 0x7f) result += char;
        else if (char === 'ü' || char === 'ä' || char === 'ö' || char === 'é' || char === '€' || char === '­') result += char;
        else fail(`canonical JSON of U+${code.toString(16).toUpperCase().padStart(4, '0')}: not known to this script, extend canonicalString()`);
    }
    return result + '"';
}

function canonical(value) {
    if (value === null)                return 'null';
    if (value === true)                return 'true';
    if (value === false)               return 'false';
    if (typeof value === 'string')     return canonicalString(value);
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value))
            fail(`canonical JSON of the number ${value}: give it as written, parseRaw()`);
        return String(value);
    }
    if (Array.isArray(value))          return '[' + value.map(canonical).join(',') + ']';
    if (value[RAW] !== undefined) {
        if (/[eE+]/.test(value[RAW]) || /^-0(\.0+)?$/.test(value[RAW]))
            fail(`canonical JSON of the number ${value[RAW]}: not written canonically`);
        return value[RAW];
    }
    return '{' + Object.keys(value).sort().map(key => canonicalString(key) + ':' + canonical(value[key])).join(',') + '}';
}


// ---- Deterministic CBOR (RFC 8949, 4.2.1) of what canonical() takes, as Styx writes the CBOR of a JSON document ---------
//
// A number with decimal places is a decimal fraction (tag 4), every other one an integer, beyond 64 bits a bignum (tags 2
// and 3); the keys of a map are in the bytewise order of their encodings, not in the order of canonical JSON.

function cborHead(major, value) {
    const n = BigInt(value);
    if (n < 24n)
        return Buffer.of(major << 5 | Number(n));
    const length = n < 0x100n ? 1 : n < 0x10000n ? 2 : n < 0x100000000n ? 4 : 8;
    return Buffer.concat([ Buffer.of(major << 5 | { 1: 24, 2: 25, 4: 26, 8: 27 }[length]), bytesOf(n, length) ]);
}

function cborInteger(n) {
    const magnitude = n < 0n ? -1n - n : n;
    if (magnitude < 1n << 64n)
        return cborHead(n < 0n ? 1 : 0, magnitude);
    const bytes = bytesOf(magnitude, Math.ceil(magnitude.toString(16).length / 2));
    return Buffer.concat([ cborHead(6, n < 0n ? 3 : 2), cborHead(2, bytes.length), bytes ]);
}

function cborNumber(text) {
    const [ , sign, integer, fraction ] = /^(-?)(\d+)(?:\.(\d+))?$/.exec(text) ?? fail(`deterministic CBOR of the number ${text}: not written canonically`);
    const mantissa = BigInt(sign + integer + (fraction ?? ''));
    return fraction === undefined
               ? cborInteger(mantissa)
               : Buffer.concat([ cborHead(6, 4), cborHead(4, 2), cborInteger(BigInt(-fraction.length)), cborInteger(mantissa) ]);
}

function cborOf(value) {
    if (value === null)                return Buffer.of(0xf6);
    if (value === true)                return Buffer.of(0xf5);
    if (value === false)               return Buffer.of(0xf4);
    if (typeof value === 'string')     return Buffer.concat([ cborHead(3, utf8(value).length), utf8(value) ]);
    if (typeof value === 'number')     return Number.isSafeInteger(value) ? cborInteger(BigInt(value)) : fail(`deterministic CBOR of the number ${value}: give it as written, parseRaw()`);
    if (Array.isArray(value))          return Buffer.concat([ cborHead(4, value.length), ...value.map(cborOf) ]);
    if (value[RAW] !== undefined)      return cborNumber(value[RAW]);
    const entries = Object.keys(value).map(key => [ cborOf(key), cborOf(value[key]) ]).sort(([ left ], [ right ]) => Buffer.compare(left, right));
    return Buffer.concat([ cborHead(5, entries.length), ...entries.flat() ]);
}


// ---- The effective tree of a version (8.2): skeletons and the tree hashes of RFC 9162 ---------------------------------
//
// For a version without templates and charging tariffs, whose effective content is its content (8.1): what the vectors
// of section 7 hold. The child arrays are read from the table of section 8.2 itself.

/** What the children of a child array are, where they have child arrays of their own: the parents of the table of 8.2. */
const CHILD_PARENTS = {
    chargingStationOperators:           'charging station operator',
    chargingPools:                      'charging pool',
    chargingStations:                   'charging station',
    eMobilityProviders:                 'e-mobility provider',
    gridOperators:                      'grid operator',
    parkingOperators:                   'parking operator',
    chargingStationManufacturers:       'charging station manufacturer',
    energyMeterManufacturers:           'energy meter manufacturer',
    transparencySoftwareManufacturers:  'transparency software manufacturer',
    conformityAssessmentBodies:         'conformity assessment body',
};

let childArraysOfSpec;

/** The child arrays of every parent, as the table of section 8.2 names them. */
function childArrays() {
    if (childArraysOfSpec !== undefined)
        return childArraysOfSpec;
    const text   = source(SPEC);
    const start  = text.indexOf('| Parent | Child arrays |');
    if (start < 0)
        fail(`${SPEC} no longer has the table of the child arrays of section 8.2`);
    childArraysOfSpec = {};
    for (const row of text.slice(start).split('\n').slice(2)) {
        if (!row.startsWith('| '))
            break;
        const [ , parent, arrays ] = row.split('|').map(cell => cell.trim());
        childArraysOfSpec[parent] = [ ...arrays.matchAll(/`([A-Za-z]+)`/g) ].map(match => match[1]);
    }
    for (const [ array, parent ] of Object.entries(CHILD_PARENTS))
        if (childArraysOfSpec[parent] === undefined || !Object.values(childArraysOfSpec).some(arrays => arrays.includes(array)))
            fail(`${SPEC}, section 8.2, no longer names the child array ${array} of ${parent}s`);
    return childArraysOfSpec;
}

const hashOf = (algorithm) => (bytes) => createHash(algorithm).update(bytes).digest();

/** The Merkle tree hash of RFC 9162, 2.1.1, of a list of byte strings. */
function mth(hash, leaves) {
    if (leaves.length === 0)
        return hash(Buffer.alloc(0));
    if (leaves.length === 1)
        return hash(Buffer.concat([ Buffer.of(0), leaves[0] ]));
    let k = 1;
    while (k * 2 < leaves.length)
        k *= 2;
    return hash(Buffer.concat([ Buffer.of(1), mth(hash, leaves.slice(0, k)), mth(hash, leaves.slice(k)) ]));
}

/** The skeleton of an entity (8.2): every child array replaced by the root and the size of the tree of its children. */
function skeletonOf(entity, parent, hash) {
    const skeleton = { ...entity };
    for (const array of childArrays()[parent] ?? [])
        if (entity[array] !== undefined)
            skeleton[array] = { '@merkleRoot': mth(hash, entity[array].map(child => utf8(canonical(skeletonOf(child, CHILD_PARENTS[array], hash))))).toString('hex'),
                                '@size':       entity[array].length };
    return skeleton;
}

/** The root of the tree of a version, its effectiveTree ETag: the digest of the skeleton of the roaming network. */
const effectiveTreeOf = (content, algorithm) => mth(hashOf(algorithm), [ utf8(canonical(skeletonOf(content, 'roaming network', hashOf(algorithm)))) ]).toString('hex');

/** The ETags of the content of a version (3, 8.3), as a commit names them: json, cbor, its effectiveTree ETags, in hex. */
const eTagsOf = (content) => [
    [ 'json', 'sha256', 'hex', sha256(utf8(canonical(content))) ],
    [ 'cbor', 'sha256', 'hex', createHash('sha256').update(cborOf(content)).digest('hex') ],
    ...(content.treeHashAlgorithms ?? [ 'sha256' ]).map(algorithm => [ 'effectiveTree', algorithm, 'hex', effectiveTreeOf(content, algorithm) ]),
];


// ---- The ETags of a document as text: json:sha256:hex:<digest> -----------------------------------------------------

function etagText(eTag, where) {
    if (!Array.isArray(eTag) || eTag.length !== 4)
        fail(`${where}: no ETag ${JSON.stringify(eTag)}`);
    const [ format, algorithm, encoding, digest ] = eTag;
    const hex = encoding === 'hex' ? digest : encoding === 'base64' ? Buffer.from(digest, 'base64').toString('hex') : fail(`${where}: ETag encoding ${encoding}`);
    return `${format}:${algorithm}:hex:${hex}`;
}


// ---- Vector files -------------------------------------------------------------------------------------------------

/** One vector file: a header saying what it is, then its vectors. */
const vectorFile = (specification, description, body) => ({ specification, description, ...body });

/** JSON as this repository writes it: two spaces, LF, a final newline. */
const serialize = (value) => JSON.stringify(value, null, 2) + '\n';

function ids(vectors, file) {
    const seen = new Set();
    for (const vector of vectors) {
        if (typeof vector.id !== 'string' || seen.has(vector.id))
            fail(`${file}: the vector id ${vector.id} is missing or used twice`);
        seen.add(vector.id);
    }
    return vectors;
}


// =====================================================================================================================
//  1. Canonical JSON and deterministic CBOR (Styx), and what POI refuses to read (section 1)
// =====================================================================================================================

function canonicalVectors() {

    // Styx/Illias/JSON/README.md, section 4: JSON input, canonical JSON, deterministic CBOR as written there.
    const table = [
        [ '{ "b" : 1, "a" : [ 1.0, 1, 1.50, 100, -2, 0.10 ], "aa" : "x", "c" : null, "d" : true }', '{"a":[1.0,1,1.50,100,-2,0.10],"aa":"x","b":1,"c":null,"d":true}', 'a5 6161 86 c482200a 01 c482211896 1864 21 c482210a 6162 01 6163 f6 6164 f5 626161 6178', 'Properties sorted, whitespace removed, decimals keep their scale; in CBOR, keys sorted by their encodings and decimals as decimal fractions.' ],
        [ '{"aa":1,"b":2,"a":3,"é":4}',                                                             '{"a":3,"aa":1,"b":2,"é":4}',                                       'a4 6161 03 6162 02 626161 01 62c3a9 04',                                                        'Ordinal order of the names in JSON, bytewise order of their encodings in CBOR.' ],
        [ '{"o":{},"a":[],"s":""}',                                                                 '{"a":[],"o":{},"s":""}',                                           'a3 6161 80 616f a0 6173 60',                                                                   'Empty containers and strings.' ],
        [ '[22000.0, -1.5, 0.000, 79228162514264337593543950335]',                                  '[22000.0,-1.5,0.000,79228162514264337593543950335]',               '84 c482201a00035b60 c482202e c4822200 c24cffffffffffffffffffffffff',                           'Decimal fractions, and the largest mantissa of a decimal as a bignum.' ],
        [ '[18446744073709551615, -9223372036854775809]',                                           '[18446744073709551615,-9223372036854775809]',                      '82 1bffffffffffffffff 3b8000000000000000',                                                     'Integers beyond 64 bit signed, as major types 0 and 1.' ],
        [ '[1.0, 1, 1.50, 0.000, -0.0, 100, 1e-7, 1.5e2, 1E-2]',                                    '[1.0,1,1.50,0.000,0.0,100,0.0000001,150,0.01]',                    undefined,                                                                                      'Exponents written out, a negative zero loses its sign.' ],
        [ '["1.10 kWh", "2026-10-12T12:00:00Z"]',                                                   '["1.10 kWh","2026-10-12T12:00:00Z"]',                              '82 68312e3130206b5768 74323032362d31302d31325431323a30303a30305a',                            'Strings stay strings: no reading, no point in time.' ],
        [ '{"b":1,"a":2,"B":3,"é":4,"aa":5,"😀":6,"｡":7}',                                          '{"B":3,"a":2,"aa":5,"b":1,"é":4,"\\uD83D\\uDE00":6,"｡":7}',         undefined,                                                                                      'UTF-16 code unit order: U+1F600 (D83D DE00) before U+FF61, and written as its escaped surrogate pair.' ],
    ];

    const vectors = table.map(([ input, canonicalJSON, cbor, description ], index) => ({
        id:           `styx-4-${String(index + 1).padStart(2, '0')}`,
        description,
        source:       `${STYX_README}, section 4`,
        input:        quoted(STYX_README, input, 'the JSON input of a vector'),
        expected:     {
            canonical:  quoted(STYX_README, canonicalJSON, 'the canonical JSON of a vector'),
            ...(cbor === undefined ? {} : { cborHex: quoted(STYX_README, cbor, 'the CBOR of a vector').replaceAll(' ', '') }),
        },
    }));

    // The deterministic CBOR this script writes for the cbor ETags of section 7, against the vectors of Styx giving it.
    for (const [ input, , cbor ] of table.filter(([ , , cbor ]) => cbor !== undefined))
        anchor(`the deterministic CBOR of ${input}`, cborOf(parseRaw(input)).toString('hex'), cbor.replaceAll(' ', ''));

    // The escaping table of Styx (section 2.3), one code point per vector, given in the input as a JSON escape so that
    // this file stays readable; the expected canonical JSON is the string as Styx writes it.
    const escaped  = [ [ 0x22, '\\"' ], [ 0x5C, '\\\\' ], [ 0x08, '\\b' ], [ 0x0C, '\\f' ], [ 0x0A, '\\n' ], [ 0x0D, '\\r' ], [ 0x09, '\\t' ],
                       ...[ 0x01, 0x1F, 0x7F, 0x85, 0xA0, 0x378, 0x2028, 0x2029, 0x1680, 0x2000, 0x200A, 0x202F, 0x205F, 0x3000, 0xE000, 0xFDD0, 0xFEFF, 0xFFFE ].map(code => [ code, undefined ]),
                       [ 0x10000, '\\uD800\\uDC00' ], [ 0x1F600, '\\uD83D\\uDE00' ], [ 0x10FFFF, '\\uDBFF\\uDFFF' ] ];
    const verbatim = [ 0x20, 0x27, 0x2B, 0x2F, 0x3C, 0x3E, 0x26, 0x60, 0x7E, 0xAD, 0xE9, 0x300, 0x600, 0x200B, 0x200D, 0x2066, 0x20AC, 0xFFF9, 0xFF61, 0xFFFD ];

    const hex4     = (code) => code.toString(16).toUpperCase().padStart(4, '0');
    const asInput  = (code) => code > 0xFFFF
                                   ? '"' + [ ...String.fromCodePoint(code) ].flatMap(c => [ c.charCodeAt(0), c.charCodeAt(1) ]).map(unit => '\\u' + hex4(unit)).join('') + '"'
                                   : `"\\u${hex4(code)}"`;

    for (const [ code, expected ] of escaped) {
        const written = expected ?? `\\u${hex4(code)}`;
        if (expected === undefined)
            quoted(STYX_TESTS, `Esc("${hex4(code)}")`, `that U+${hex4(code)} is escaped`);
        vectors.push({
            id:           `styx-escape-${hex4(code)}`,
            description:  `U+${hex4(code)} is escaped${code === 0x378 ? ' (unassigned in the Unicode version of the runtime: see section 5 of the Styx README)' : ''}.`,
            source:       `${STYX_README}, section 2.3; ${STYX_TESTS}`,
            input:        asInput(code),
            expected:     { canonical: `"${written}"` },
        });
    }

    for (const code of verbatim) {
        quoted(STYX_TESTS, `0x${code.toString(16).toUpperCase()}`, `that U+${hex4(code)} is written as it is`);
        vectors.push({
            id:           `styx-verbatim-${hex4(code)}`,
            description:  `U+${hex4(code)} is written as it is, in UTF-8.`,
            source:       `${STYX_README}, section 2.3; ${STYX_TESTS}`,
            input:        asInput(code),
            expected:     { canonical: `"${String.fromCodePoint(code)}"` },
        });
    }

    vectors.push({
        id:           'styx-lone-surrogate',
        description:  'An unpaired surrogate is written as U+FFFD.',
        source:       `${STYX_README}, section 2.3`,
        input:        '"\\uD800x"',
        expected:     { canonical: '"�x"' },
    });
    quoted(STYX_README, 'A string MUST NOT contain an unpaired surrogate; Styx writes U+FFFD instead', 'what it writes for an unpaired surrogate');

    // What a reader MUST refuse (SPECIFICATION.md section 1, Styx section 1), and what RFC 8259 does not call JSON at all.
    const refuse = [
        [ 'decimal-scale',         '1e-30',                                   'decimalOutOfRange', 'More than 28 decimal places: a decimal can not hold it as written.' ],
        [ 'decimal-scale-2',       '1.0000000000000000000000000000000001',    'decimalOutOfRange', 'More than 28 decimal places.' ],
        [ 'decimal-mantissa',      '7922816251426433759354395033.6',          'decimalOutOfRange', 'A mantissa above 96 bits.' ],
        [ 'duplicate-property',    '{"a":1,"a":2}',                           'duplicateProperty', 'An object names a property twice.' ],
        [ 'duplicate-nested',      '{"x":{"b":true,"b":true}}',               'duplicateProperty', 'A nested object names a property twice, the same value both times.' ],
        [ 'trailing-comma-array',  '[1,]',                                    'syntax',            'RFC 8259: no trailing comma in an array.' ],
        [ 'trailing-comma-object', '{"a":1,}',                                'syntax',            'RFC 8259: no trailing comma in an object.' ],
        [ 'comment',               '{"a":1/* a comment */}',                  'syntax',            'RFC 8259: JSON has no comments.' ],
        [ 'single-quotes',         "{'a':1}",                                 'syntax',            'RFC 8259: strings are written in double quotes.' ],
        [ 'unquoted-name',         '{a:1}',                                   'syntax',            'RFC 8259: names are strings.' ],
        [ 'nan',                   '[NaN]',                                   'syntax',            'RFC 8259: NaN is no number.' ],
        [ 'infinity',              '[Infinity]',                              'syntax',            'RFC 8259: Infinity is no number.' ],
        [ 'leading-zero',          '[01]',                                    'syntax',            'RFC 8259: no leading zeros.' ],
        [ 'leading-plus',          '[+1]',                                    'syntax',            'RFC 8259: no leading plus.' ],
        [ 'bare-fraction',         '[.5]',                                    'syntax',            'RFC 8259: a fraction needs an integer part.' ],
        [ 'trailing-dot',          '[1.]',                                    'syntax',            'RFC 8259: a fraction needs digits.' ],
        [ 'hex-number',            '[0x10]',                                  'syntax',            'RFC 8259: no hexadecimal numbers.' ],
        [ 'invalid-escape',        '["\\x41"]',                               'syntax',            'RFC 8259: \\x is no escape.' ],
        [ 'raw-control-character', '["a\tb"]',                                'syntax',            'RFC 8259: a control character in a string must be escaped.' ],
        [ 'second-value',          '{"a":1} {"b":2}',                         'syntax',            'Two JSON texts are not one: what follows the first value must not be dropped silently.' ],
        [ 'unclosed',              '{"a":[1,2}',                              'syntax',            'Not closed.' ],
        [ 'empty',                 '',                                        'syntax',            'No JSON text at all.' ],
    ];

    quoted(SPEC, 'MUST be refused, not rounded; so MUST an object that names a property twice.', 'that decimals and duplicates are refused');
    quoted(SPEC, 'without quotes, `01` and `0x10`, a raw control character in a string, and a second value after the first.', 'that what RFC 8259 does not call JSON is refused');

    const invalidInputs = refuse.map(([ id, input, expectedError, description ]) => ({
        id:            `refuse-${id}`,
        description,
        source:        expectedError === 'syntax' ? 'RFC 8259; ' + `${STYX_README}, section 1` : `${SPEC}, section 1; ${STYX_README}, section 1`,
        input,
        expectedError,
    }));

    return vectorFile(
        'Styx canonical JSON and deterministic CBOR (libs/Styx/Styx/Illias/JSON/README.md); WWCP POI 3 SPECIFICATION.md section 1',
        'JSON text read as POI reads what it hashes (decimals as decimals, strings as strings), written as canonical JSON and as deterministic CBOR; and JSON text a reader must refuse.',
        { vectors: ids(vectors, 'canonical'), invalidInputs: ids(invalidInputs, 'canonical (invalid)') });

}


// =====================================================================================================================
//  2. Base64 and Base45
// =====================================================================================================================

function encodingVectors() {

    const base64 = [
        { id: 'base64-1', description: 'Three bytes, no padding.',                           text: 'AAEC', hex: '000102' },
        { id: 'base64-2', description: 'One byte, two padding characters.',                  text: 'AA==', hex: '00' },
        { id: 'base64-3', description: 'Two bytes, one padding character.',                  text: 'AQI=', hex: '0102' },
    ];
    const base64Invalid = [
        { id: 'base64-invalid-1', description: 'Padding bits that are not zero: not the canonical encoding of any bytes (RFC 4648, 3.5).', text: 'AB==' },
        { id: 'base64-invalid-2', description: 'Without its padding.',                         text: 'AA' },
        { id: 'base64-invalid-3', description: 'The URL alphabet (RFC 4648, 5) is another encoding.', text: 'A-B_' },
        { id: 'base64-invalid-4', description: 'Whitespace within.',                           text: 'AA E' },
    ];

    // RFC 9285, section 4.
    const base45 = [
        { id: 'base45-rfc9285-1', description: 'RFC 9285, 4.3: "AB".',       text: 'BB8',          hex: Buffer.from('AB').toString('hex') },
        { id: 'base45-rfc9285-2', description: 'RFC 9285, 4.3: "Hello!!".',  text: '%69 VD92EX0',  hex: Buffer.from('Hello!!').toString('hex') },
        { id: 'base45-rfc9285-3', description: 'RFC 9285, 4.3: "base-45".',  text: 'UJCLQE7W581',  hex: Buffer.from('base-45').toString('hex') },
        { id: 'base45-rfc9285-4', description: 'RFC 9285, 4.4: "ietf!".',    text: 'QED8WEX0',     hex: Buffer.from('ietf!').toString('hex') },
    ];
    const base45Invalid = [
        { id: 'base45-invalid-1', description: 'RFC 9285, 6: "GGW" decodes to 65535 + 1, more than two bytes hold.', text: 'GGW' },
        { id: 'base45-invalid-2', description: 'A lowercase letter is no Base45 character.',                         text: 'bb8' },
        { id: 'base45-invalid-3', description: 'One character alone encodes nothing.',                               text: 'BB8A' },
    ];

    for (const vector of [ ...base45 ])
        anchor(`Base45 ${vector.text}`, fromBase45(vector.text).toString('hex'), vector.hex);

    return vectorFile(
        'RFC 4648 Base64 (canonical: padding, zero padding bits) as POI reads keys and signature values; RFC 9285 Base45 as the QR code of a trust anchor holds its CBOR',
        'Text decoded to bytes, and text a reader must refuse.',
        { base64: ids(base64, 'base64'), base64Invalid: ids(base64Invalid, 'base64 (invalid)'), base45: ids(base45, 'base45'), base45Invalid: ids(base45Invalid, 'base45 (invalid)') });

}


// =====================================================================================================================
//  3. The examples of SPECIFICATION.md, section 6
// =====================================================================================================================

function specificationVectors() {

    const S = (text, what) => quoted(SPEC, text, what);

    const content        = S('{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/v1","@id":"rn1","chargingStationOperators":[{"@id":"DE*GEF","chargingPools":[{"@id":"DE*GEF*P1","chargingStations":[{"@id":"DE*GEF*S1","EVSEs":[{"@id":"DE*GEF*E1*1","created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z","maxPower":22000,"maxVoltage":230.5}],"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z"}],"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z"}],"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z","name":{"en":"Charging Station Operator \'DE*GEF\'"}}],"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z","name":{"en":"Example"}}', 'the content of the example');
    const eTags          = [ S('json:sha256:hex:5592afaf5dfcceebc17c8a29f4493e061406f648b76a6fee8b6fe15d553c7108', 'the json ETag'),
                             S('cbor:sha256:hex:567697f19947efa4679a0e401e1e7c5f528ffb7ca0d3d7928d3b2ed02abef52d', 'the cbor ETag'),
                             S('effectiveTree:sha256:hex:84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a', 'the effectiveTree ETag') ];

    anchor('the json ETag of the content', 'json:sha256:hex:' + sha256(utf8(content)), eTags[0]);

    // Section 8.2: the skeletons bottom-up and their digests, SHA-256(0x00 || skeleton).
    const skeletons = [
        [ 'EVSE',                      '{"@id":"DE*GEF*E1*1","created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z","maxPower":22000,"maxVoltage":230.5}', 'f37f52daaf5db8a3db648ac8ea7f3ef9955a1afff133803d1a9ff84b99fdc443' ],
        [ 'charging station',          '{"@id":"DE*GEF*S1","EVSEs":{"@merkleRoot":"f37f52daaf5db8a3db648ac8ea7f3ef9955a1afff133803d1a9ff84b99fdc443","@size":1},"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z"}', 'd111c66efd73a1ff910cf674270046cfe3b6a2e0cab85034993df80025623f40' ],
        [ 'charging pool',             '{"@id":"DE*GEF*P1","chargingStations":{"@merkleRoot":"d111c66efd73a1ff910cf674270046cfe3b6a2e0cab85034993df80025623f40","@size":1},"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z"}', '8d4f6ed9ca2ffabf1862488a9cff9c8a224a86a247a9bb48b33751d0df5042fe' ],
        [ 'charging station operator', '{"@id":"DE*GEF","chargingPools":{"@merkleRoot":"8d4f6ed9ca2ffabf1862488a9cff9c8a224a86a247a9bb48b33751d0df5042fe","@size":1},"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z","name":{"en":"Charging Station Operator \'DE*GEF\'"}}', 'd76ebfb110df2bf7c0db6194f69dc563ab2349189580ccfa0a1292e71d90d3fd' ],
        [ 'roaming network, the root', '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/v1","@id":"rn1","chargingStationOperators":{"@merkleRoot":"d76ebfb110df2bf7c0db6194f69dc563ab2349189580ccfa0a1292e71d90d3fd","@size":1},"created":"2026-01-01T00:00:00.000Z","lastChange":"2026-01-01T00:00:00.000Z","name":{"en":"Example"}}', '84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a' ],
    ].map(([ what, skeleton, digest ], index) => {
        S(skeleton, `the skeleton of the ${what}`);
        S(digest,   `the digest of the ${what}`);
        anchor(`the digest of the skeleton of the ${what}`, sha256(Buffer.concat([ Buffer.of(0), utf8(skeleton) ])), digest);
        return { id: `spec-6-skeleton-${index + 1}`, description: `The skeleton of the ${what} and its digest SHA-256(0x00 || skeleton) (8.2).`, skeleton, hashAlgorithm: 'sha256', digest };
    });

    anchor('the root of the tree is the effectiveTree ETag', 'effectiveTree:sha256:hex:' + skeletons[4].digest, eTags[2]);

    // What section 7 calculates of a version, for the version of section 6.
    anchor('the cbor ETag of the content',  'cbor:sha256:hex:' + sha256(cborOf(parseRaw(content))),                 eTags[1]);
    anchor('the effective tree of the content', 'effectiveTree:sha256:hex:' + effectiveTreeOf(parseRaw(content), 'sha256'), eTags[2]);

    // The ETags of a content calculated here (3.1): of its canonical JSON, of its deterministic CBOR, its effectiveTree;
    // the three anchored on the content of the example.
    const eTagTextsOf = (version) => eTagsOf(version).map((eTag, index) => etagText(eTag, `the ETag ${index} of a content`));

    anchor('the ETags of the content of the example', eTagTextsOf(parseRaw(content)).join(', '), eTags.join(', '));

    // Custom data (section 2) is held as given: numbers with their decimal places and of any size, texts as texts, also
    // those that look like timestamps, in every time zone, nested as given; so is the custom data of an address
    // (csharp-review 20, 21). The content of the example, one of its entities giving custom data, and its ETags.
    S('places (`1.50`), and texts as texts, also those that look like timestamps, in every time zone; so is the custom', 'that custom data is held as given');

    const basis = `${SPEC}, section 2 (custom data)`;

    const customDataContent = (name, description, review, change) => {
        const version = parseRaw(content);
        const [ operator ] = version.chargingStationOperators, [ pool ] = operator.chargingPools, [ station ] = pool.chargingStations, [ evse ] = station.EVSEs;
        change({ network: version, operator, pool, station, evse });
        return { id: `spec-2-custom-data-${name}`, description, basis: `${basis}; csharp-review ${review}`, content: canonical(version), eTags: eTagTextsOf(version) };
    };

    const customDataContents = [
        customDataContent('decimals', 'The EVSE of the example with custom data of decimals: their decimal places kept (1.50, 0.10, 0.000), and digits a binary floating-point number does not hold.', 20,
                          ({ evse })     => evse.customData     = parseRaw('{"beyondDouble":0.1000000000000000055511151231,"manyDigits":12345678901234567.123456789,"negative":-0.5,"price":0.39,"scale":1.50,"small":0.0000001,"tenth":0.10,"zero":0.000}')),
        customDataContent('integers', 'The charging station of the example with custom data of integers beyond the safe integers of a binary floating-point number, beyond 64 bits and beyond the mantissa of a decimal.', 20,
                          ({ station })  => station.customData  = parseRaw('{"beyond64Bits":18446744073709551616,"beyondDouble":9007199254740993,"decimalMax":79228162514264337593543950335,"huge":123456789012345678901234567890123456789,"negative":-9223372036854775809,"uint64Max":18446744073709551615}')),
        customDataContent('texts', 'The charging pool of the example with custom data of texts that look like timestamps, in UTC, with an offset and without one, or like numbers: texts, in every time zone.', 20,
                          ({ pool })     => pool.customData     = parseRaw('{"date":"2026-10-26","negativeOffset":"2026-10-26T07:00:00-05:00","noZone":"2026-10-26T12:00:00","number":"1.50","offset":"2026-10-26T14:00:00+02:00","reading":"1.10 kWh","utc":"2026-10-26T12:00:00Z","utcMillis":"2026-10-26T12:00:00.000Z"}')),
        customDataContent('address', 'The charging station operator of the example with an address giving custom data: a decimal, an integer beyond 64 bits and a timestamp with an offset, kept with the address.', 21,
                          ({ operator }) => operator.address    = parseRaw('{"city":{"de":"Jena"},"country":"DEU","customData":{"floorArea":120.50,"meterId":18446744073709551616,"openedAt":"2026-10-26T08:00:00+01:00"},"houseNumber":"1a","postalCode":"07745","street":"Tatzendpromenade"}')),
        customDataContent('nested', 'The roaming network of the example with custom data of a JSON-LD context, objects and arrays nesting decimals, integers, texts that look like timestamps, and booleans.', 20,
                          ({ network })  => network.customData  = parseRaw('{"@context":"https://example.org/contexts/custom/v1","readings":[1.50,"1.10 kWh",18446744073709551616,true,"2026-10-26T14:00:00+02:00"],"tariff":{"currency":"EUR","price":0.390,"validFrom":"2026-10-26T00:00:00+01:00"}}')),
    ];

    // Identifications: the digest of the canonical JSON of a commit without its @id (5.1, 11.3).
    const genesisContent = S('{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v3","eTags":[["json","sha256","hex","5592afaf5dfcceebc17c8a29f4493e061406f648b76a6fee8b6fe15d553c7108"],["cbor","sha256","hex","567697f19947efa4679a0e401e1e7c5f528ffb7ca0d3d7928d3b2ed02abef52d"],["effectiveTree","sha256","hex","84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a"]],"revision":0,"roamingNetworkId":"rn1"}', 'the content of the genesis commit');
    const genesisId      = S('498e076a90b8d71254c017a80d164442abaa99b4d11d4deb9b8c86576917c29a', 'the identification of the genesis commit');
    const epoch2Content  = S('{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v3","eTags":[["json","sha256","hex","5592afaf5dfcceebc17c8a29f4493e061406f648b76a6fee8b6fe15d553c7108"],["cbor","sha256","hex","567697f19947efa4679a0e401e1e7c5f528ffb7ca0d3d7928d3b2ed02abef52d"],["effectiveTree","sha256","hex","84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a"]],"epoch":2,"profiles":{"canonicalization":"styx-canonical-json-v1","checkpoint":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/checkpoint/v1","commit":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v3","identificationHash":"sha512","priceStatement":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/priceStatement/v1","signatureAlgorithms":["Ed25519","ML-DSA-65"]},"revision":0,"roamingNetworkId":"rn1"}', 'the content of the genesis of epoch 2');
    const epoch2Id       = S('ae070918e0d75696682a5d28ecf31216ef8b87a4872740facc3f5945b1c0d9616b1ddaa131d472016d08b2418e4c206700a2d2f9056f977731f4272fe26b8b34', 'the identification of the genesis of epoch 2');

    anchor('the identification of the genesis commit',  sha256(utf8(genesisContent)), genesisId);
    anchor('the identification of the genesis of epoch 2', sha512(utf8(epoch2Content)), epoch2Id);

    const commits = [
        { id: 'spec-6-commit-genesis', description: 'The genesis commit: the SHA-256 of its content (5.1).',                                                        commit: { '@id': genesisId, ...JSON.parse(genesisContent) }, content: genesisContent, hashAlgorithm: 'sha256', commitId: genesisId },
        { id: 'spec-6-commit-epoch-2', description: 'The genesis of a second epoch: SHA-512 identifications, Ed25519 and ML-DSA-65 (11.3).',                            commit: { '@id': epoch2Id,  ...JSON.parse(epoch2Content)  }, content: epoch2Content,  hashAlgorithm: 'sha512', commitId: epoch2Id },
    ];

    // Keys, thumbprints and signatures (4.1, 5.4, 8.5, 8.6, 12.1), all Ed25519 of the private seeds the section names.
    const keys = {
        leader:  { seed: S('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f', 'the seed of the leader key'),        publicKey: S('d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=', 'the leader key') },
        rno:     { seed: S('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'the seed of the attestation key'),   publicKey: S('Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=', 'the attestation key') },
        alpha:   { seed: S('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f', 'the seed of the identity key'),      publicKey: S('i7BOHBuD3d8xH1vN33xQ7ePAgC9H7HluKhMc9BKY2fM=', 'the identity key') },
        beta:    { seed: S('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'the seed of the identity key of Beta'), publicKey: undefined },
        gef:     { seed: S('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', 'the seed of the price statement key'), publicKey: S('JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=', 'the price statement key') },
    };

    for (const [ name, key ] of Object.entries(keys)) {
        const derived = ed25519(key.seed).publicKey;
        if (key.publicKey !== undefined)
            anchor(`the public key of the seed of '${name}'`, derived, key.publicKey);
        key.publicKey = derived;
    }

    // The COSE keys (RFC 9052, OKP) the section gives and their RFC 9679 thumbprints, the @ids of POI keys. With exactly
    // the required members, a COSE key in deterministic CBOR is the thumbprint input itself.
    const coseKeys = [
        [ 'the identity key of DE*RNO, of Alpha', 'owEBIAYhWCCLsE4cG4Pd3zEfW83ffFDt48CAL0fseW4qExz0EpjZ8w==', '1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802', keys.alpha.publicKey ],
        [ 'the identity key of Beta',             'owEBIAYhWCAc5WpIyC/5kWKhS8VEYSZ05dYfuTF+ZdQFV4D9vLTcNQ==', 'a287cebcd93b836a712b6393a914a86e63516d401285f3c642f734a28146f83f', keys.beta.publicKey ],
        [ 'the signing key of Alpha',             'owEBIAYhWCAprLrhQbzK8LIuGpTTTQvHNh5SbQv+EsiXlLyTIpZt1w==', 'ea671729aa29c6140b5129b8d59e13fd9fbd4b96e37b3c5185fb11c3eeeac554', keys.rno.publicKey ],
    ].map(([ what, cose, id, publicKey ], index) => {
        S(cose, `the COSE key of ${what}`);
        S(id,   `the @id of ${what}`);
        const bytes = Buffer.from(cose, 'base64');
        anchor(`the thumbprint of ${what}`, sha256(bytes), id);
        anchor(`the raw public key in the COSE key of ${what}`, bytes.subarray(bytes.length - 32).toString('base64'), publicKey);
        return { id: `spec-6-key-${index + 1}`, description: `The COSE key of ${what} and its RFC 9679 thumbprint, its @id (4.1).`, coseKey: cose, keyId: id, algorithm: 'Ed25519', rawPublicKey: publicKey };
    });

    S('8cb46c0f98440da34ad4af304431f76c7cb7462fa8fdfd5d6261dc685809220d', 'the @id of the price statement key');

    const signed = [
        [ 'the leader signature of the genesis commit (5.4)', keys.leader, '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/commitSignature/v1","algorithm":"Ed25519","commit":{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v3","@id":"498e076a90b8d71254c017a80d164442abaa99b4d11d4deb9b8c86576917c29a","eTags":[["json","sha256","hex","5592afaf5dfcceebc17c8a29f4493e061406f648b76a6fee8b6fe15d553c7108"],["cbor","sha256","hex","567697f19947efa4679a0e401e1e7c5f528ffb7ca0d3d7928d3b2ed02abef52d"],["effectiveTree","sha256","hex","84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a"]],"revision":0,"roamingNetworkId":"rn1"},"keyId":"leader","role":"leader","signedAt":"2026-10-12T12:00:00.000Z","signer":"leader.example.org"}', 'x/h7//+MgkH18ljzmyXAIoirilwduHRjK9j/9/vKZIOPyO2Ir1eSbvfFkj1kSy9TwTIeMdqLAU22aOj7g1cGAA==' ],
        [ 'the attestation of the genesis commit (8.5)',      keys.rno,    '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/attestation/v1","algorithm":"Ed25519","commitId":"498e076a90b8d71254c017a80d164442abaa99b4d11d4deb9b8c86576917c29a","eTag":["effectiveTree","sha256","hex","84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a"],"keyId":"rno","revision":0,"roamingNetworkId":"rn1","role":"roamingNetworkOperator","signedAt":"2026-10-17T18:00:00.000Z","signer":"DE*RNO","validUntil":"2026-10-17T18:15:00.000Z"}', 'enreFD6NAwKbGJBHryNsNNtgFn2wbVlI+w1PqplrkNzmnFSMPrvRp+AC1XVmUdeZ6jYh9BD1VoP/Iihq2YJ1CA==' ],
        [ 'the key statement of DE*RNO (8.6)',               keys.alpha,  '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/keyStatement/v3","algorithm":"Ed25519","identityKeys":[{"@id":"1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802","key":"owEBIAYhWCCLsE4cG4Pd3zEfW83ffFDt48CAL0fseW4qExz0EpjZ8w=="}],"keyId":"1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802","minConsensus":1,"roamingNetworkId":"rn1","roamingNetworkOperatorId":"DE*RNO","signedAt":"2026-10-17T00:00:00.000Z","validUntil":"2026-11-16T00:00:00.000Z"}', 'ismqBONH+YxKTywJdYYovEUT6JkZQ4t0xl3nGB8cJTfn3d7hTX/PoUjO+518kESsmgHuRZ4aenyMRutWKfinCw==' ],
        [ 'the key statement of a quorum, by Alpha (4.1, 8.6)', keys.alpha, '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/keyStatement/v3","algorithm":"Ed25519","identityKeys":[{"@id":"1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802","holder":"Alpha","key":"owEBIAYhWCCLsE4cG4Pd3zEfW83ffFDt48CAL0fseW4qExz0EpjZ8w=="},{"@id":"a287cebcd93b836a712b6393a914a86e63516d401285f3c642f734a28146f83f","holder":"Beta","key":"owEBIAYhWCAc5WpIyC/5kWKhS8VEYSZ05dYfuTF+ZdQFV4D9vLTcNQ=="}],"keyId":"1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802","minConsensus":2,"roamingNetworkId":"rn1","roamingNetworkOperatorId":"DE*RNO","signedAt":"2026-10-17T00:00:00.000Z","validUntil":"2026-11-16T00:00:00.000Z"}', 'FZyTQgtDgx3qvcVnBwQU0c4iyNT4CLIWXg1Lr/oF/YLMyRNwZXuWIhwusnDim5eW7++hApGcyrbeGruURLGQAg==' ],
        [ 'the certificate of a signing key of Alpha (8.6)',  keys.alpha,  '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/signingKeyCertificate/v2","algorithm":"Ed25519","keyId":"1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802","roamingNetworkOperatorId":"DE*RNO","signedAt":"2026-10-17T00:00:00.000Z","signingKey":{"@id":"ea671729aa29c6140b5129b8d59e13fd9fbd4b96e37b3c5185fb11c3eeeac554","holder":"Alpha","key":"owEBIAYhWCAprLrhQbzK8LIuGpTTTQvHNh5SbQv+EsiXlLyTIpZt1w==","notAfter":"2027-10-17T00:00:00.000Z","usages":["party"]}}', 'QndT4IDJA/YPtnq47eZKRvELDUDEiXkEe9qHTzgIkjwNYPhkKuaTksr8iOb4aqahqS/+QSzcjJVx0M6bz5jICg==' ],
        [ 'the price statement of DE*GEF*E1*1 (12.1)',        keys.gef,    '{"@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/priceStatement/v1","algorithm":"Ed25519","entityId":"DE*GEF*E1*1","entityType":"EVSE","keyId":"8cb46c0f98440da34ad4af304431f76c7cb7462fa8fdfd5d6261dc685809220d","priceStatus":{"prices":[{"chargingTariffId":"DE*GEF*T1","elements":[{"priceComponents":[{"price":0.39,"stepSize":1,"type":"ENERGY"}]}]}]},"roamingNetworkId":"rn1","role":"chargingStationOperator","sequence":0,"signedAt":"2026-10-19T11:59:58.000Z","signer":"DE*GEF","validFrom":"2026-10-19T12:00:00.000Z","validUntil":"2026-10-19T12:15:00.000Z"}', 'On32sQ3JD5yUHL3CDnc0XA9+wpfEVw9wvXF3exh+rpcWOmBoD/tuvFBmNcolWWV5lOxF54JC5aJ0PmX9gPERAw==' ],
    ];

    // The signature of Beta on the key statement of the quorum: the same input with its own keyId (8.6).
    const betaInput = signed[3][2].replace('"keyId":"1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802","minConsensus"', '"keyId":"a287cebcd93b836a712b6393a914a86e63516d401285f3c642f734a28146f83f","minConsensus"');
    signed.push([ 'the key statement of a quorum, by Beta (4.1, 8.6)', keys.beta, betaInput, 'IAYgeNI2NS/atdxYZW8ty/1IjBUTTqmkjE0tgW3fjs+3xDbaIhZrsHLWVV9y7MyMrD2K8zKpJ2w1P0DNzjo1Dw==' ]);

    /** A key as POI writes it: its COSE key in Base64 and its @id, the RFC 9679 thumbprint; and its raw bytes. */
    const publicKeyOf = (raw) => ({ coseKey: coseKeyOf(raw), keyId: sha256(Buffer.from(coseKeyOf(raw), 'base64')), rawPublicKey: raw });

    for (const key of coseKeys)
        anchor(`the COSE key of ${key.description}`, coseKeyOf(key.rawPublicKey), key.coseKey);

    const signatures = signed.map(([ what, key, input, value ], index) => {
        if (key !== keys.beta)
            S(input, `the signature input of ${what}`);
        S(value, `the signature value of ${what}`);
        anchor(`the Ed25519 signature of ${what}`, ed25519(key.seed).sign(input), value);
        if (!ed25519Verify(key.publicKey, input, value))
            fail(`anchor: the signature of ${what} does not verify`);
        return { id: `spec-6-signature-${index + 1}`, description: `The signature input of ${what}, its value and the key, Ed25519.`, algorithm: 'Ed25519', ...publicKeyOf(key.publicKey), privateSeed: key.seed, input, value };
    });

    // The same signatures must fail for an input of one more byte, and for a value of another signature.
    const invalidSignatures = [
        { id: 'spec-6-signature-invalid-1', description: 'The leader signature over its input with one more space.',           algorithm: 'Ed25519', ...publicKeyOf(keys.leader.publicKey), input: signatures[0].input + ' ', value: signatures[0].value },
        { id: 'spec-6-signature-invalid-2', description: 'The value of the attestation for the input of the leader signature.', algorithm: 'Ed25519', ...publicKeyOf(keys.leader.publicKey), input: signatures[0].input,       value: signatures[1].value },
        { id: 'spec-6-signature-invalid-3', description: 'The attestation verified with the key of the leader.',               algorithm: 'Ed25519', ...publicKeyOf(keys.leader.publicKey), input: signatures[1].input,       value: signatures[1].value },
    ];

    // Price statement digest (12.1): the SHA-256 of its signature input, "value" left out; the statement with "value"
    // added, which sorts last.
    const priceStatement = signatures[5].input.slice(0, -1) + `,"value":"${signatures[5].value}"}`;
    const priceDigest    = S('4cecb5d6ef7506ad518455d13d958c6b892d9fe8e70d1d7901f6fc5aa1d0f880', 'the digest of the price statement');
    anchor('the digest of the price statement', sha256(utf8(signatures[5].input)), priceDigest);

    // The trust anchor (8.6): its JSON form and its QR code.
    const trustAnchorJSON = S('{"@id":"rn1","@context":"https://open.charging.cloud/contexts/wwcp/roamingNetwork/trustAnchor/v2","urls":["https://hub.example/poi/RNs/rn1","https://mirror.example/poi/RNs/rn1"],"keys":["1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802"],"name":{"en":"Example"}}', 'the trust anchor');
    const qrCode          = S('WWCP/TA-2:*+KJ684VC:KE:A6/PD-FF$FGW24.+U3M0-$O1JV%LLP-T2OR-7U%J0WP7ZXAW7RI33:PKFFMRD0..DF$D4IK1$CM2D$9FQ$DTVDMVC.KE5REG8FA9DIWENPEJ/5B9DOICB$CBECP9ESZCS9EHDDAIACPE:KEJB6XF4MWEW9E0G7 :5*ED0LEPJEB$CBECP9ESZCS9EHDDAIACPE:KE3B6D68-3E7WEBAFB9FA9DIWENPEJ/5/3E1$C+%5 8D$KEZED:1DRPC34E.TCUPCG/DB$CLWE10684F98E0LEBECZEDV2D7$CK4F-KE/:56LE QEAC8NPC04E00651', 'the QR code of the trust anchor');
    const decoded         = trustAnchorOfQRCode(qrCode);
    anchor('the trust anchor of the QR code', canonical(parseRaw(JSON.stringify(decoded))), canonical(parseRaw(trustAnchorJSON)));
    anchor('the CBOR of the QR code', String(fromBase45(qrCode.slice('WWCP/TA-2:'.length)).length), S('223 bytes', 'the size of the CBOR').split(' ')[0]);

    return vectorFile(
        'WWCP POI 3 SPECIFICATION.md, section 6, and section 2 on custom data (libs/WWCP_POI/SPECIFICATION.md)',
        'The examples of the specification, every value as written there: the content of a version, its ETags and its effective tree, identifications, keys, signatures, a price statement and a trust anchor; and the content of the example with custom data, held as given (section 2), its ETags calculated here.',
        {
            contents:          ids([ { id: 'spec-6-content', description: 'The content of the example version, its canonical JSON, and its ETags (2, 3, 8.2).', content, eTags }, ...customDataContents ], 'specification (contents)'),
            skeletons,
            commits,
            keys:              coseKeys,
            signatures,
            invalidSignatures,
            priceStatements:   [ { id: 'spec-6-price-statement', description: 'The price statement of DE*GEF*E1*1 with its value, and its digest (12.1).', statement: priceStatement, digest: priceDigest } ],
            trustAnchors:      [ { id: 'spec-6-trust-anchor', description: 'The trust anchor of the example at two servers, its JSON form and its QR code (8.6).', json: trustAnchorJSON, qrCode, roamingNetworkId: decoded['@id'], urls: decoded.urls, keys: decoded.keys, minConsensus: decoded.minConsensus ?? 1 } ],
        });

}

/** The JSON form of a trust anchor of its QR code: `WWCP/TA-2:` and the Base45 of its CBOR, the key @ids as 32 bytes each. */
function trustAnchorOfQRCode(text) {
    if (!text.startsWith('WWCP/TA-2:'))
        fail(`no trust anchor: ${text.slice(0, 20)}`);
    const map  = decodeCbor(fromBase45(text.slice('WWCP/TA-2:'.length)));
    // One entry of keys per holder: the thumbprint of its key, or the array of the thumbprints of its keys.
    const hex  = (key) => Buffer.from(key).toString('hex');
    const json = { '@id': map['@id'], '@context': map['@context'], urls: map.urls, keys: map.keys.flatMap(key => Array.isArray(key) ? key.map(hex) : [ hex(key) ]) };
    if (map.name         !== undefined) json.name         = map.name;
    if (map.description  !== undefined) json.description  = map.description;
    if (map.minConsensus !== undefined) json.minConsensus = map.minConsensus;
    return json;
}


// =====================================================================================================================
//  4. Trust: station proofs of the example network, signed with the keys of section 6
// =====================================================================================================================
//
// The roaming network rn1 of section 6, its operator DE*RNO now with the quorum of section 6 - the identity keys of
// Alpha and Beta, minConsensus 2, the key statement both signed - and a signing key of each holder, certified by the
// identity key of its holder: the one of Alpha is the attestation key of section 6, the one of Beta of a seed of its
// own. Where Alpha holds a second identity key, of a seed of its own, it names two holders of the trust anchor. A station proof of DE*GEF*S1 as section 6 gives it, with attestations of its root, and variants of it, each
// signed anew: what the trust rules of 8.4 to 8.6 take and refuse. Ed25519 signatures are deterministic, and so is
// every byte below.

const CONTEXT = 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/';

function trustVectors() {

    const S = (text, what) => quoted(SPEC, text, what);

    const seeds = {
        alphaIdentity:  S('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f', 'the seed of the identity key of Alpha'),
        betaIdentity:   S('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'the seed of the identity key of Beta'),
        alphaSigning:   S('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'the seed of the signing key of Alpha'),
        betaSigning:    '505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f',
        outsider:       'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
        alphaIdentity2: 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef',
        forgedBeta:     'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
    };

    const key = (seed, more = {}) => {
        const pair = ed25519(seed);
        const cose = coseKeyOf(pair.publicKey);
        const id   = sha256(Buffer.from(cose, 'base64'));
        return { ...pair, id, json: { '@id': id, key: cose, ...more } };
    };

    const alphaIdentity = key(seeds.alphaIdentity, { holder: 'Alpha' });
    const betaIdentity  = key(seeds.betaIdentity,  { holder: 'Beta' });
    const outsider      = key(seeds.outsider,      { holder: 'Beta' });
    const alphaIdentity2 = key(seeds.alphaIdentity2, { holder: 'Alpha' });

    /** The same key, its holder named otherwise. */
    const namedAs = (identity, holder) => ({ ...identity, json: { ...identity.json, holder } });

    /** Keys as a key statement and the roaming network operator write them: in the order of their @ids. */
    const inOrder = (keys) => [ ...keys ].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0).map(identity => identity.json);

    anchor('the identity key of Alpha', alphaIdentity.id, S('1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802', 'its @id'));
    anchor('the identity key of Beta',  betaIdentity.id,  S('a287cebcd93b836a712b6393a914a86e63516d401285f3c642f734a28146f83f', 'its @id'));

    const signingKey = (seed, holder, more = {}) => key(seed, { notAfter: '2027-10-17T00:00:00.000Z', holder, usages: [ 'party' ], ...more });

    /** A signed object of POI: its fields, signed as the canonical JSON of them with its context, algorithm and keyId. */
    const signedBy = (signer, context, fields) => {
        const input = canonical({ '@context': context, algorithm: 'Ed25519', keyId: signer.id, ...fields });
        return { algorithm: 'Ed25519', keyId: signer.id, value: signer.sign(input) };
    };

    const keyStatement = ({ operatorId = 'DE*RNO', signers = [ alphaIdentity, betaIdentity ], identityKeys = [ alphaIdentity, betaIdentity ] } = {}) => {
        const fields = { roamingNetworkId: 'rn1', roamingNetworkOperatorId: operatorId, identityKeys: inOrder(identityKeys), minConsensus: 2,
                         signedAt: '2026-10-17T00:00:00.000Z', validUntil: '2026-11-16T00:00:00.000Z' };
        return { ...fields, signatures: signers.map(signer => signedBy(signer, CONTEXT + 'keyStatement/v3', fields)) };
    };

    const certificate = (signing, certifier, { operatorId = 'DE*RNO' } = {}) => {
        const fields = { roamingNetworkOperatorId: operatorId, signedAt: '2026-10-17T00:00:00.000Z', signingKey: signing.json };
        return { ...fields, ...signedBy(certifier, CONTEXT + 'signingKeyCertificate/v2', fields) };
    };

    const alphaSigning   = signingKey(seeds.alphaSigning, 'Alpha');
    const betaSigning    = signingKey(seeds.betaSigning,  'Beta');
    const certificates   = [ certificate(alphaSigning, alphaIdentity), certificate(betaSigning, betaIdentity) ];

    // The anchors: the key statement of the quorum and the certificate of section 6 are those this scenario makes.
    {
        const statement = keyStatement();
        anchor('the signature of Alpha on the key statement of the quorum', statement.signatures[0].value, S('FZyTQgtDgx3qvcVnBwQU0c4iyNT4CLIWXg1Lr/oF/YLMyRNwZXuWIhwusnDim5eW7++hApGcyrbeGruURLGQAg==', 'it'));
        anchor('the signature of Beta on the key statement of the quorum',  statement.signatures[1].value, S('IAYgeNI2NS/atdxYZW8ty/1IjBUTTqmkjE0tgW3fjs+3xDbaIhZrsHLWVV9y7MyMrD2K8zKpJ2w1P0DNzjo1Dw==', 'it'));
        anchor('the certificate of the signing key of Alpha', certificates[0].value, S('QndT4IDJA/YPtnq47eZKRvELDUDEiXkEe9qHTzgIkjwNYPhkKuaTksr8iOb4aqahqS/+QSzcjJVx0M6bz5jICg==', 'it'));
    }

    // The tree of DE*GEF as section 6 gives it, its digest the one of section 6: only the operator of the network is new.
    const evse        = { '@id': 'DE*GEF*E1*1', maxPower: 22000, maxVoltage: { [RAW]: '230.5' }, created: '2026-01-01T00:00:00.000Z', lastChange: '2026-01-01T00:00:00.000Z' };
    const leafOf      = (entity) => ({ '@size': 1, '@leaves': [ { '@index': 0, '@auditPath': [], '@entity': entity } ] });
    const stationOf   = (e)      => ({ '@id': 'DE*GEF*S1', created: '2026-01-01T00:00:00.000Z', lastChange: '2026-01-01T00:00:00.000Z', EVSEs: [ e ] });
    const operatorOf  = (e)      => ({ '@id': 'DE*GEF', name: { en: S("Charging Station Operator 'DE*GEF'", 'the name of DE*GEF') }, created: '2026-01-01T00:00:00.000Z', lastChange: '2026-01-01T00:00:00.000Z',
                                       chargingPools: leafOf({ '@id': 'DE*GEF*P1', created: '2026-01-01T00:00:00.000Z', lastChange: '2026-01-01T00:00:00.000Z', chargingStations: leafOf(stationOf(e)) }) });
    const gefDigest   = S('d76ebfb110df2bf7c0db6194f69dc563ab2349189580ccfa0a1292e71d90d3fd', 'the digest of DE*GEF');

    const rnoOf = ({ statement = keyStatement(), certificates: certified, identityKeys = [ alphaIdentity, betaIdentity ] }) => ({
        '@id': 'DE*RNO', name: { en: 'Roaming Network Operator' }, minConsensus: 2,
        keyStatement: statement, signingKeyCertificates: certified, identityKeys: inOrder(identityKeys),
        created: '2026-01-01T00:00:00.000Z', lastChange: '2026-01-01T00:00:00.000Z',
    });

    const networkOf = (rno, e = evse) => ({
        '@context': CONTEXT + 'v1', '@id': 'rn1', name: { en: 'Example' }, created: '2026-01-01T00:00:00.000Z', lastChange: '2026-01-01T00:00:00.000Z',
        operator: rno, chargingStationOperators: leafOf(operatorOf(e)),
    });

    // The root (8.2): bottom-up, each child array of one child pruned to the digest of that child, SHA-256(0x00 ||
    // skeleton), which is the root of the array; the roaming network operator, its keys and certificates are part of
    // the skeleton of the network.
    const digestOf = (skeleton) => sha256(Buffer.concat([ Buffer.of(0), utf8(canonical(skeleton)) ]));
    const pruned   = (digest)   => ({ '@merkleRoot': digest, '@size': 1 });
    const only     = (array)    => array['@leaves'][0]['@entity'];

    const rootOf = (network) => {
        const operator  = only(network.chargingStationOperators);
        const pool      = only(operator.chargingPools);
        const station   = only(pool.chargingStations);
        const stationD  = digestOf({ ...station,  EVSEs:                    pruned(digestOf(station.EVSEs[0])) });
        const poolD     = digestOf({ ...pool,     chargingStations:         pruned(stationD) });
        const operatorD = digestOf({ ...operator, chargingPools:            pruned(poolD) });
        return            digestOf({ ...network,  chargingStationOperators: pruned(operatorD) });
    };

    anchor('the digest of DE*GEF, as section 6 gives it', (() => { const network = networkOf(undefined); const operator = only(network.chargingStationOperators);
                                                                    const pool = only(operator.chargingPools); const station = only(pool.chargingStations);
                                                                    return digestOf({ ...operator, chargingPools: pruned(digestOf({ ...pool, chargingStations: pruned(digestOf({ ...station, EVSEs: pruned(digestOf(station.EVSEs[0])) })) })) }); })(),
           gefDigest);

    // The same root for the network of section 6, which has no operator: the anchor for rootOf().
    {
        const { operator: _, ...plain } = networkOf(undefined);
        anchor('the root of the network of section 6', rootOf(plain), S('84acb445aa41df13e83b7af61f25a8387dc65c0c7e83b29b907e9ed06045b44a', 'the root'));
    }

    // The commit the proofs name: of no published history. A proof names it, its attestations sign it; a verifier of
    // a proof does not recalculate it.
    const commitId = sha256(utf8('WWCPPOIConformanceTests: the commit of the station proofs of poi-trust.json'));

    const attestation = (signer, root, { at = '2026-10-17T18:00:00.000Z', until = '2026-10-17T18:15:00.000Z', role = 'roamingNetworkOperator', subject, networkId = 'rn1' } = {}) => {
        const fields = { roamingNetworkId: networkId, commitId, revision: 0, eTag: [ 'effectiveTree', 'sha256', 'hex', root ], role, signer: 'DE*RNO', signedAt: at,
                         ...(until === null ? {} : { validUntil: until }), ...(subject === undefined ? {} : { subject }) };
        return { ...fields, ...signedBy(signer, CONTEXT + 'attestation/v1', fields) };
    };

    const proofText = (network, attestations) =>
        canonical({ '@context': CONTEXT + 'proof/v1', hashAlgorithm: 'sha256', commitId, revision: 0, roamingNetwork: network, attestations });

    /** A proof of the station: a network, and the attestations `attest` makes of its root. */
    const proofOf = ({ network = networkOf(rnoOf({ certificates })), attest = (root) => [ attestation(alphaSigning, root), attestation(betaSigning, root) ] } = {}) => {
        const root = rootOf(network);
        return { text: proofText(network, attest(root)), root };
    };

    const trustAnchor = ({ keys = [ alphaIdentity.id, betaIdentity.id ], minConsensus = 2 } = {}) =>
        canonical({ '@id': 'rn1', '@context': CONTEXT + 'trustAnchor/v2', urls: [ 'https://hub.example/poi/RNs/rn1', 'https://mirror.example/poi/RNs/rn1' ], keys, minConsensus, name: { en: 'Example' } });

    const vectors = [];
    const vector  = (id, expected, description, basis, { proof = proofOf(), anchor: trust = trustAnchor(), at = '2026-10-17T18:05:00.000Z', ...more } = {}) =>
        vectors.push({ id: `trust-${id}`, description, basis, expected, trustAnchor: trust, at, evseId: 'DE*GEF*E1*1', root: `effectiveTree:sha256:hex:${proof.root}`, proof: proof.text, ...more });

    const B = (section) => `${SPEC}, ${section}`;

    const withKey = (signing, certifier = betaIdentity) =>
        proofOf({ network: networkOf(rnoOf({ certificates: [ certificates[0], certificate(signing, certifier) ] })), attest: (root) => [ attestation(alphaSigning, root), attestation(signing, root) ] });

    vector('valid',                'accepted', 'Attested by the signing keys of both holders, each certified by the identity key of its holder, which the trust anchor pins; within the validity of the attestations.', B('8.4 to 8.6'));
    vector('expired',              'refused',  'A minute after the attestations ended (validUntil).', B('8.5'), { at: '2026-10-17T18:16:00.000Z' });
    vector('future',               'refused',  'A second before the attestations were signed, the key statement and the certificates valid: an attestation of the future is no attestation now.', `${B('8.5, Validity')}; csharp-review 7`,
           { at: '2026-10-17T17:59:59.000Z' });
    vector('one-holder',           'refused',  'Attested by Alpha only, where the quorum takes two holders.', B('8.5, Trust'),
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root) ] }) });
    vector('one-holder-twice',     'refused',  'Attested twice by the signing key of Alpha: one holder.', B('8.5, Trust'),
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root), attestation(alphaSigning, root, { at: '2026-10-17T18:01:00.000Z', until: '2026-10-17T18:16:00.000Z' }) ] }) });
    vector('subject',              'refused',  'Alpha attests the root, Beta only the digest of DE*GEF (a subject): a subject attests one entity, not the root, and does not count for the proof.', `${B('8.5, Subject')}; csharp-review 6`,
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root), attestation(betaSigning, root, { subject: { entityType: 'ChargingStationOperator', entityId: 'DE*GEF', digest: gefDigest } }) ] }) });
    vector('role',                 'refused',  'Beta attests the root in the role of a witness: the roaming network operator attests its versions.', `${B('8.5')}; csharp-review 6`,
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root), attestation(betaSigning, root, { role: 'witness' }) ] }) });
    vector('no-valid-until',       'refused',  'Attestations without validUntil, two weeks later, the key statement and the certificates still valid: an attestation gives its validUntil, so that none is valid forever.', `${B('8.5, Validity')}; csharp-review 7`,
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root, { until: null }), attestation(betaSigning, root, { until: null }) ] }), at: '2026-11-01T00:00:00.000Z' });
    vector('a-day',                'accepted', 'Attestations valid for 24 hours, the longest an attestation is valid, an hour before they end.', `${B('8.5, Validity')}; csharp-review 7`,
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root, { until: '2026-10-18T18:00:00.000Z' }), attestation(betaSigning, root, { until: '2026-10-18T18:00:00.000Z' }) ] }), at: '2026-10-18T17:00:00.000Z' });
    vector('too-long',             'refused',  'Attestations valid for 24 hours and a millisecond, checked within them: an attestation is valid for 24 hours at most.', `${B('8.5, Validity')}; csharp-review 7`,
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root, { until: '2026-10-18T18:00:00.001Z' }), attestation(betaSigning, root, { until: '2026-10-18T18:00:00.001Z' }) ] }) });
    vector('certificate-operator', 'refused',  'The certificate of the signing key of Beta names another roaming network operator.', `${B('8.6')}; csharp-review 19`,
           { proof: proofOf({ network: networkOf(rnoOf({ certificates: [ certificates[0], certificate(betaSigning, betaIdentity, { operatorId: 'DE*XYZ' }) ] })) }) });
    vector('statement-operator',   'refused',  'The key statement names another roaming network operator.', `${B('8.6')}; csharp-review 19`,
           { proof: proofOf({ network: networkOf(rnoOf({ statement: keyStatement({ operatorId: 'DE*XYZ' }), certificates })) }) });
    vector('usage',                'refused',  'The signing key of Beta may sign tariffs only, not for the party.', B('8.5, Trust; 4.1'),
           { proof: withKey(signingKey(seeds.betaSigning, 'Beta', { usages: [ 'tariffs' ] })) });
    vector('key-expired',          'refused',  'The signing key of Beta expired before it attested (notAfter).', B('8.6'),
           { proof: withKey(signingKey(seeds.betaSigning, 'Beta', { notAfter: '2026-10-17T12:00:00.000Z' })) });
    vector('key-ended',            'refused',  'The signing key of Beta ended (notAfter) after it attested and before the time checked, its attestation still valid: the key of an attestation is valid when it attested and when it is checked, its signedAt being the choice of its signer.', `${B('8.5, Validity; 8.6')}; csharp-review 7`,
           { proof: withKey(signingKey(seeds.betaSigning, 'Beta', { notAfter: '2026-10-17T18:02:00.000Z' })) });
    vector('certified-by-other',   'refused',  'The signing key of Beta certified by the identity key of Alpha: each holder certifies its own signing keys only.', B('8.6'),
           { proof: withKey(betaSigning, alphaIdentity) });
    vector('uncertified',          'refused',  'Beta attests with a key no certificate names.', B('8.5, Trust'),
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root), attestation(signingKey(seeds.outsider, 'Beta'), root) ] }) });
    vector('anchor-other-keys',    'refused',  'A trust anchor pinning other identity keys.', B('8.6'),
           { anchor: trustAnchor({ keys: [ outsider.id, betaIdentity.id ] }) });
    vector('anchor-quorum-1',      'refused',  'A trust anchor of minConsensus 1, Alpha alone attesting: the quorum of the key statement, two, is the larger.', B('8.6'),
           { anchor: trustAnchor({ minConsensus: 1 }), proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root) ] }) });
    vector('other-network',        'refused',  'Beta attests a version of another roaming network.', B('8.5'),
           { proof: proofOf({ attest: (root) => [ attestation(alphaSigning, root), attestation(betaSigning, root, { networkId: 'rn2' }) ] }) });
    vector('entity',               'refused',  'The EVSE changed after the attestations: the proof leads to another root than they attest.', B('8.4'),
           { proof: (() => { const signed = rootOf(networkOf(rnoOf({ certificates }))); const changed = networkOf(rnoOf({ certificates }), { ...evse, maxPower: 350000 });
                             return { text: proofText(changed, [ attestation(alphaSigning, signed), attestation(betaSigning, signed) ]), root: rootOf(changed) }; })() });
    vector('signature',            'refused',  'The signature of Beta replaced by the one of Alpha.', B('8.5'),
           { proof: proofOf({ attest: (root) => { const alpha = attestation(alphaSigning, root); return [ alpha, { ...attestation(betaSigning, root), value: alpha.value } ]; } }) });

    // The holders of a quorum are counted as the trust anchor names them, never as a key statement or a key names itself
    // (csharp-review 1): the trust anchor names the two identity keys of Alpha as one holder.
    const alphaTwice  = trustAnchor({ keys: [ [ alphaIdentity.id, alphaIdentity2.id ].sort(), betaIdentity.id ] });
    const forgedBeta  = signingKey(seeds.forgedBeta, 'Beta');

    vector('holder-keys',          'accepted', 'The trust anchor names the two identity keys of Alpha as one holder, the key statement names both as keys of Alpha and is signed by the second one and by Beta; attested by Alpha and Beta.', B('8.6, Trust anchor'),
           { anchor: alphaTwice,
             proof:  proofOf({ network: networkOf(rnoOf({ statement:     keyStatement({ identityKeys: [ alphaIdentity, alphaIdentity2, betaIdentity ], signers: [ alphaIdentity2, betaIdentity ] }),
                                                          certificates,
                                                          identityKeys:  [ alphaIdentity, alphaIdentity2, betaIdentity ] })) }) });
    vector('holder-renamed',       'refused',  'Alpha names its second identity key as one of Beta in a key statement it signs with both, certifies a signing key of "Beta" with that key and attests with both signing keys: the trust anchor names both identity keys as one holder, the statement names their holders otherwise and is refused.', `${B('8.6, Verification')}; csharp-review 1`,
           { anchor: alphaTwice,
             proof:  (() => { const identityKeys = [ alphaIdentity, namedAs(alphaIdentity2, 'Beta'), betaIdentity ];
                              return proofOf({ network: networkOf(rnoOf({ statement: keyStatement({ identityKeys, signers: [ alphaIdentity, alphaIdentity2 ] }), certificates: [ certificates[0], certificate(forgedBeta, alphaIdentity2) ], identityKeys })),
                                               attest:  (root) => [ attestation(alphaSigning, root), attestation(forgedBeta, root) ] }); })() });
    vector('holder-unnamed-key',   'refused',  'The key statement, signed by Alpha and Beta, names the second identity key of Alpha only; the operator names the first one as one of "Beta", which certifies a signing key of "Beta": the trust anchor names that key as one of Alpha, so its attestation counts for Alpha, and Alpha alone attests.', `${B('8.6, Verification')}; csharp-review 1`,
           { anchor: alphaTwice,
             proof:  proofOf({ network: networkOf(rnoOf({ statement:     keyStatement({ identityKeys: [ alphaIdentity2, betaIdentity ], signers: [ alphaIdentity2, betaIdentity ] }),
                                                          certificates:  [ certificate(alphaSigning, alphaIdentity2), certificate(forgedBeta, namedAs(alphaIdentity, 'Beta')) ],
                                                          identityKeys:  [ namedAs(alphaIdentity, 'Beta'), alphaIdentity2, betaIdentity ] })),
                               attest:  (root) => [ attestation(alphaSigning, root), attestation(forgedBeta, root) ] }) });

    return vectorFile(
        'WWCP POI 3 SPECIFICATION.md, sections 8.4 to 8.6 (libs/WWCP_POI/SPECIFICATION.md)',
        'Station proofs of the example network of section 6, its operator holding the quorum of section 6, signed with the Ed25519 keys of section 6 and two seeds of their own: what a verifier must take and refuse, checked against a trust anchor at a point in time. Trust anchors and proofs are JSON text, to be read as POI reads JSON.',
        { stationProofs: ids(vectors, 'trust') });

}


// =====================================================================================================================
//  5. What the C# examples published: the frozen run
// =====================================================================================================================

function walk(directory) {
    return readdirSync(directory, { withFileTypes: true })
               .flatMap(entry => entry.isDirectory() ? walk(join(directory, entry.name)) : [ join(directory, entry.name) ])
               .sort();
}

const runFile  = (path) => relative(RUN_DIR, path).split(sep).join('/');
const readRun  = (file) => readFileSync(join(RUN_DIR, file), 'utf8');
const jsonRun  = (file) => JSON.parse(readRun(file));
const rawRun   = (file) => parseRaw(readRun(file));

function historyVectors() {

    const files = walk(RUN_DIR).map(runFile);

    const versions          = [];
    const commits           = [];
    const checkpoints       = [];
    const checkpointProofs  = [];
    const priceStatements   = [];
    const trustAnchors      = [];
    const stationProofs     = [];

    const commitsById       = new Map();
    const checkpointsById   = new Map();

    const addCommit = (file, pointer, commit) => {
        const epoch = commit.epoch ?? 1;
        commits.push({ id: `commit:${file}#${pointer}`, file, pointer, commitId: commit['@id'], roamingNetworkId: commit.roamingNetworkId, epoch, revision: commit.revision,
                       hashAlgorithm: commit['@id'].length === 128 ? 'sha512' : commit['@id'].length === 96 ? 'sha384' : 'sha256',
                       eTags: commit.eTags.map((eTag, index) => etagText(eTag, `${file}#${pointer}/eTags/${index}`)) });
        commitsById.set(commit['@id'], commit);
    };

    const addCheckpoint = (file, pointer, checkpoint) => {
        if (checkpointsById.has(checkpoint['@id']))
            return;
        checkpoints.push({ id: `checkpoint:${file}#${pointer}`, file, pointer, checkpointId: checkpoint['@id'], roamingNetworkId: checkpoint.roamingNetworkId,
                           epoch: checkpoint.epoch ?? 1, sequence: checkpoint.sequence, revision: checkpoint.revision, commitId: checkpoint.commitId, final: checkpoint.final === true });
        checkpointsById.set(checkpoint['@id'], { file, pointer });
    };

    /** A version: a roaming network with its commit; the ETags its commit names, which those it lists must equal. */
    const addVersion = (file, pointer, network, commit) => {
        const listed = network.eTags?.map((eTag, index) => etagText(eTag, `${file}#${pointer}/eTags/${index}`));
        const named  = commit?.eTags.map((eTag, index) => etagText(eTag, `${file}: the commit's eTags/${index}`));
        if (listed !== undefined && named !== undefined && listed.join() !== named.join())
            fail(`${file}#${pointer}: the ETags the roaming network lists are not those of its commit`);
        versions.push({ id: `version:${file}#${pointer}`, file, pointer, roamingNetworkId: network['@id'],
                        ...(commit === undefined ? {} : { commitId: commit['@id'], epoch: commit.epoch ?? 1, revision: commit.revision }),
                        eTags: named ?? listed });
    };

    for (const file of files) {

        if (file.endsWith('.txt') && file.includes('trustAnchor')) {
            const text    = readRun(file).trim();
            const decoded = trustAnchorOfQRCode(text);
            trustAnchors.push({ id: `trustAnchor:${file}`, file, roamingNetworkId: decoded['@id'], urls: decoded.urls, keys: decoded.keys, minConsensus: decoded.minConsensus ?? 1, json: canonical(parseRaw(JSON.stringify(decoded))) });
            continue;
        }

        if (!file.endsWith('.json'))
            continue;

        const json = jsonRun(file);
        const name = file.split('/').pop();

        // Snapshots, the genesis and archive segments: a version with its commit, maybe a checkpoint.
        if (json.roamingNetwork !== undefined && json.commit !== undefined && json.hashAlgorithm === undefined) {
            addVersion(file, '/roamingNetwork', json.roamingNetwork, json.commit);
            addCommit (file, '/commit', json.commit);
            if (json.checkpoint !== undefined)
                addCheckpoint(file, '/checkpoint', json.checkpoint);
        }

        if (json.base !== undefined && json.info !== undefined) {
            addVersion(file, '/base/roamingNetwork', json.base.roamingNetwork, json.base.commit);
            addCommit (file, '/base/commit', json.base.commit);
            json.commits.forEach((commit, index) => addCommit(file, `/commits/${index}`, commit));
        }

        if (name === 'QA.json')
            addVersion(file, '', json, undefined);

        if (name.startsWith('QA-commit') || name.includes('commits-since') || name.includes('commits-to-head')) {
            if (Array.isArray(json)) json.forEach((commit, index) => addCommit(file, `/${index}`, commit));
            else                     addCommit(file, '', json);
        }

        if (/^QA-(epoch-2-)?checkpoint-\d+\.json$/.test(name))
            addCheckpoint(file, '', json);

        if (name.startsWith('evidence-'))
            json.checkpoints.forEach((checkpoint, index) => addCheckpoint(file, `/checkpoints/${index}`, checkpoint));

    }

    // Checkpoint proofs (10.4), each against the checkpoint it names.
    for (const file of files.filter(file => /proof-revision-\d+(-archived)?\.json$/.test(file))) {
        const proof = jsonRun(file);
        const at    = checkpointsById.get(proof.checkpointId) ?? fail(`${file}: no checkpoint ${proof.checkpointId} in the run`);
        checkpointProofs.push({ id: `checkpointProof:${file}`, file, pointer: '', checkpoint: at, checkpointId: proof.checkpointId, commitId: proof.leaf.commitId, revision: proof.leaf.revision, index: proof['@index'], size: proof['@size'] });
    }
    {
        const file  = 'driver/evidence-DE_GEF_E1_1.json';
        const proof = jsonRun(file).commitProof;
        checkpointProofs.push({ id: `checkpointProof:${file}#/commitProof`, file, pointer: '/commitProof', checkpoint: checkpointsById.get(proof.checkpointId) ?? fail(`${file}: no checkpoint of its commit proof`),
                                checkpointId: proof.checkpointId, commitId: proof.leaf.commitId, revision: proof.leaf.revision, index: proof['@index'], size: proof['@size'] });
    }

    // Price statements (12): their digests, re-derived here, anchored on the `previous` of every next statement.
    const statementFiles = files.filter(file => /priceStatements(-DE_GEF_E1_1)?\.json$/.test(file) || file.endsWith('malleated-twin.json') || file.startsWith('driver/evidence-'));
    const byDigest       = new Map();

    for (const file of statementFiles) {
        const raw  = rawRun(file);
        const list = Array.isArray(raw) ? raw.map((statement, index) => [ `/${index}`, statement ])
                   : raw.priceStatements !== undefined ? raw.priceStatements.map((statement, index) => [ `/priceStatements/${index}`, statement ])
                   : [ [ '', raw ] ];
        for (const [ pointer, statement ] of list) {
            // The signature input (12.1): the statement with its @context, "value" left out.
            const { value: _value, ...signed } = statement;
            const withContext = { '@context': 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/priceStatement/v1', ...signed };
            const digest      = sha256(utf8(canonical(withContext)));
            byDigest.set(digest, true);
            priceStatements.push({ id: `priceStatement:${file}#${pointer}`, file, pointer, roamingNetworkId: statement.roamingNetworkId, entityType: statement.entityType, entityId: statement.entityId,
                                   sequence: Number(statement.sequence[RAW]), algorithm: statement.algorithm, keyId: statement.keyId, digest,
                                   ...(statement.previous === undefined ? {} : { previous: statement.previous }) });
        }
    }

    for (const statement of priceStatements.filter(statement => statement.previous !== undefined))
        if (!byDigest.has(statement.previous))
            fail(`anchor: the previous ${statement.previous} of ${statement.id} is the digest of no price statement of the run`);

    // Station proofs (8.4): the root they lead to, and that they verify against the trust anchor of their epoch at AT.
    const anchorOfEpoch = (epoch) => epoch === 1 ? 'published/QA-trustAnchor.txt' : 'published/QA-trustAnchor-mldsa.txt';
    for (const file of files.filter(file => file.endsWith('-proof.json') || /proofs\/QA-proof-(station|evse)-/.test(file))) {
        const proof    = jsonRun(file);
        const commit   = commitsById.get(proof.commitId) ?? fail(`${file}: the commit ${proof.commitId} of the proof is not in the run`);
        const tree     = commit.eTags.find(eTag => eTag[0] === 'effectiveTree' && eTag[1] === proof.hashAlgorithm) ?? fail(`${file}: the commit names no tree of ${proof.hashAlgorithm}`);
        const complete = [];
        const walkProof = (node) => { for (const [ key, value ] of Object.entries(node)) {
            if (key === 'chargingStations' && value['@leaves'] !== undefined) for (const leaf of value['@leaves']) if (Array.isArray(leaf['@entity'].EVSEs)) complete.push({ chargingStationId: leaf['@entity']['@id'], evseIds: leaf['@entity'].EVSEs.map(evse => evse['@id']) });
            if (value !== null && typeof value === 'object') walkProof(value); } };
        walkProof(proof.roamingNetwork);
        stationProofs.push({ id: `stationProof:${file}`, file, pointer: '', trustAnchor: anchorOfEpoch(commit.epoch ?? 1), at: AT, commitId: proof.commitId, revision: proof.revision,
                             hashAlgorithm: proof.hashAlgorithm, root: etagText(tree, file), chargingStations: complete, expected: 'accepted' });
    }
    {
        const file     = 'driver/evidence-DE_GEF_E1_1.json';
        const evidence = jsonRun(file);
        const proof    = evidence.chargingStationProof;
        const commit   = commitsById.get(proof.commitId) ?? fail(`${file}: the commit of its proof is not in the run`);
        stationProofs.push({ id: `stationProof:${file}#/chargingStationProof`, file, pointer: '/chargingStationProof', trustAnchor: anchorOfEpoch(commit.epoch ?? 1), at: evidence.chargingStarted,
                             commitId: proof.commitId, revision: proof.revision, hashAlgorithm: proof.hashAlgorithm,
                             root: etagText(commit.eTags.find(eTag => eTag[0] === 'effectiveTree' && eTag[1] === proof.hashAlgorithm), file), chargingStations: [ { chargingStationId: null, evseIds: [ evidence.EVSEId ] } ], expected: 'accepted' });
    }

    // The whole history, commit by commit (examples A4 to A13): epoch 1 from its genesis with every checkpoint, the
    // genesis of epoch 2 every server makes from the final checkpoint, epoch 2 up to the head QA.json is.
    const epoch1 = [ 'published/QA-commits-since-genesis.json', 'published/QA-commits-since-checkpoint-2.json', 'published/QA-commits-since-checkpoint-4.json', 'published/QA-commits-since-checkpoint-5.json' ];
    // The head of epoch 2: the last commit MakeProofs gave, revision 11 since example A15 - QA.json and QA-commit.json are
    // the head examples A13 and A14 left, revision 8, one of the commits before it.
    const toHead = jsonRun('proofs/QA-epoch-2-commits-to-head.json');
    const head   = toHead.at(-1);
    const shown  = jsonRun('published/QA-commit.json');
    if (!toHead.some(commit => commit['@id'] === shown['@id'] && commit.revision === shown.revision))
        fail('proofs/QA-epoch-2-commits-to-head.json: QA-commit.json is none of its commits');
    const replays = [ {
        id:           'replay-QA-both-epochs',
        description:  'The history of QA from its genesis: every commit of epoch 1 with its change set applied and its owners checked, the checkpoints 0 to 6 (6 the final one), the genesis of epoch 2, and every commit of epoch 2 with its checkpoint 0, up to the head.',
        // What the replay checks is the content: change sets, the signatures of their owners, ETags, identifications,
        // checkpoint lines, epochs. Who may sign commits and checkpoints is a matter of trust, the verifier's (examples
        // A6 and A11); the signatures of commits and checkpoints are taken unchecked.
        commitAndCheckpointSignatures: 'unchecked',
        steps: [
            { op: 'fromSnapshot',    file: 'published/QA-genesis.json' },
            ...epoch1.map(file => ({ op: 'append', file })),
            ...[ 0, 1, 2, 3, 4, 5, 6 ].map(sequence => ({ op: 'takeCheckpoint', file: `published/QA-checkpoint-${sequence}.json` })),
            { op: 'expectHead',      epoch: 1, revision: 16, commitId: jsonRun('published/QA-checkpoint-6.json').commitId },
            { op: 'startNextEpoch',  genesisCommitId: jsonRun('published/QA-epoch-2-genesis.json').commit['@id'] },
            { op: 'append',          file: 'proofs/QA-epoch-2-commits-to-head.json' },
            { op: 'takeCheckpoint',  file: 'published/QA-epoch-2-checkpoint-0.json' },
            { op: 'expectHead',      epoch: 2, revision: head.revision, commitId: head['@id'], eTags: head.eTags.map((eTag, index) => etagText(eTag, `QA-epoch-2-commits-to-head.json/${toHead.length - 1}/eTags/${index}`)) },
        ],
    } ];

    for (const [ name, list ] of Object.entries({ versions, commits, checkpoints, checkpointProofs, priceStatements, trustAnchors, stationProofs }))
        ids(list, `history (${name})`);

    return vectorFile(
        `WWCP POI 3 (libs/WWCP_POI), as its C# examples A1 to A15 published it in one run: test-vectors/runs/${RUN}`,
        'What a roaming network, its servers, its witnesses and a driver\'s app published, public data only, frozen as the reference implementation wrote it. Each entry names a document of the run (file and JSON pointer) and what an implementation must calculate of it, or that it must accept it.',
        { run: `runs/${RUN}`, at: AT, versions, commits, checkpoints, checkpointProofs, priceStatements, trustAnchors, stationProofs, replays });

}


// =====================================================================================================================
//  6. What an implementation must refuse
// =====================================================================================================================

/** A JSON pointer (RFC 6901) into a document, for the patches below to be checked before they are written. */
function at(document, pointer) {
    let value = document;
    for (const token of pointer.split('/').slice(1).map(token => token.replaceAll('~1', '/').replaceAll('~0', '~'))) {
        if (value === null || typeof value !== 'object' || !(token in value))
            fail(`the pointer ${pointer} names nothing`);
        value = value[token];
    }
    return value;
}

/**
 * Versions read as WWCP_POI3 reads them, refused in the words both give: `RoamingNetwork.TryParse` and the TryParse of each
 * entity, what the constructor of each refuses of what it read, the references the constructor of the network checks, the
 * values it writes otherwise than given, the offers of an operator overlapping (9.4), the public keys of energy meters as
 * BouncyCastle makes them. WWCP_POI.TS reads a version so since `813e1d7`, `2cbfe60` and `7c4d16e`, which it probed against
 * WWCP_POI3 at `89d2e02`; these vectors are of its cases. QA of the run without its eTags, changed so that only what the
 * vector is about is refused. Where QA has no entity of a kind, with those of a richer QA, as WWCP_POI.TS tests it
 * (`tests/richNetwork.ts`): at DE*GEF a charging pool template, a charging tariff template, a tariff group, a pool group, an
 * offer, a brand and a parking space, DE*GEF*P1 at a grid connection point, an e-mobility provider with a group and an
 * offer, a grid operator with a grid connection point, a meter group and a meter template, a parking operator with a
 * garage, a space, a sensor, a template, a group and a product. A reason leaves out the `(Parameter '...')` .NET appends to
 * the message of an ArgumentException, which names a parameter of a constructor, not what is refused; and the vectors
 * name no decimal with places in a reason, which WWCP_POI3 words in the culture of its machine.
 */
function readAsWWCP_POI3({ qa, named, patched, refuse, notHeld, gefAt, pool1, pool2, tariffAt, templateAt, bsi, DOCS, HELD, ORDER }) {

    const doc        = (name) => `${DOCS}/${name}.md`;
    const RICH_AT    = '2026-11-05T19:43:46.188Z';
    const meta       = { created: RICH_AT, lastChange: RICH_AT };
    if (!(Date.parse(qa.created) <= Date.parse(RICH_AT) && Date.parse(RICH_AT) <= Date.parse(qa.lastChange)))
        fail(`QA.json: ${RICH_AT}, when the richer QA adds its entities, is not within the life of the roaming network`);

    const stationS1  = named(`${pool1}/chargingStations/0`, 'DE*GEF*S1');
    const evseE11    = named(`${stationS1}/EVSEs/0`, 'DE*GEF*E1*1');
    const evseE12    = named(`${stationS1}/EVSEs/1`, 'DE*GEF*E1*2');
    const stAC       = named(`${gefAt}/chargingStationTemplates/0`, 'DE*GEF*ST_AC');
    const emtAC      = named(`${gefAt}/energyMeterTemplates/0`, 'DE*GEF*EMT_AC');
    const emtDC      = named(`${gefAt}/energyMeterTemplates/1`, 'DE*GEF*EMT_DC');
    const groupAC    = named(`${gefAt}/EVSEGroups/0`, 'DE*GEF*EG_AC');
    const gd         = named('/chargingStationManufacturers/0', 'GraphDefined');
    const gdAC44     = named(`${gd}/chargingStationModels/0`, 'GD-AC44');
    const kdm500     = named(`${named('/energyMeterManufacturers/0', 'KERNBERG')}/energyMeterModels/0`, 'KDM-500');
    const tsm        = named('/transparencySoftwareManufacturers/0', 'GraphDefined');
    const release    = named(`${tsm}/transparencySoftware/0`, 'GraphDefined:chargy-1.5.0');
    const component  = `${tariffAt}/elements/0/priceComponents/0`;
    const meterKey   = `${evseE11}/energyMeter/publicKeys/0`;
    const pools      = at(qa, `${gefAt}/chargingPools`).map((_, index) => `${gefAt}/chargingPools/${index}`);
    const status     = at(qa, `${emtDC}/transparencySoftwareStatus/0`);

    if (at(qa, `${stationS1}/EVSEs`).length !== 2 || 'maxPower' in at(qa, stationS1) || at(qa, `${templateAt}/chargingConnectors/0/format`) !== 'SOCKET' ||
        'cableLength' in at(qa, `${templateAt}/chargingConnectors/0`) || 'vat' in at(qa, component) || at(qa, `${component}/type`) !== 'ENERGY' ||
        at(qa, `${gdAC44}/hardwareRevisions`).join() !== '1.0' || at(qa, `${emtAC}/hardwareRevision`) !== '1.4' || at(qa, `${kdm500}/signatureMethods`).join() !== 'OCMF' ||
        at(qa, `${evseE11}/maxPower`) !== 150000 || at(qa, `${emtAC}/role`) !== 'evse' || at(qa, `${tariffAt}/currency`) !== 'EUR')
        fail('QA.json: DE*GEF and the parties of QA are no longer what the vectors of reading change');

    const ofOperator = (error) => `The given JSON representation of a charging station operator is invalid: ${error}`;
    const ofNetwork  = (error) => `The given JSON representation of a roaming network is invalid: ${error}`;
    const holds      = (text)  => `the content holds it as '${text}'`;
    const LEAVES     = 'the content leaves it out';
    const notHeldAt  = (path, reason) => `'${path}' is not written as the content holds it: ${reason}!`;

    // QA with an entity of every kind WWCP_POI3 reads that QA has none of, as the given change leaves them.
    const richer = (change = () => undefined) => {
        const parts = {
            poolTemplates:    [ { '@id': 'DE*GEF*PT_STD', name: { en: 'Standard' }, facilities: [ 'CAFE' ], ...meta } ],
            tariffTemplates:  [ { '@id': 'DE*GEF*TT_BASE', currency: 'EUR', ...meta } ],
            tariffGroups:     [ { '@id': 'DE*GEF*TG_ALL', name: { en: 'All' }, chargingTariffIds: [ 'DE*GEF*T_AC' ], ...meta } ],
            poolGroups:       [ { '@id': 'DE*GEF*PG_ALL', name: { en: 'All' }, chargingPoolIds: [ 'DE*GEF*P1' ], ...meta } ],
            offers:           [ { '@id': 'offer-1', name: { en: 'Ten off' }, discount: { percent: 10, dimensions: [ 'ENERGY' ] }, EVSEGroupIds: [ 'DE*GEF*EG_AC' ], ...meta } ],
            brands:           [ { '@id': 'GEF-Brand', name: { en: 'GEF' } } ],
            parkingSpaces:    [ { '@id': 'gef-space-1', ...meta } ],
            providers:        [ { '@id': 'DE-GDF', name: { en: 'GDF' },
                                  EVSEGroups: [ { '@id': 'DE*GDF*EG_FAV', name: { en: 'Favourites' }, EVSEIds: [ 'DE*GEF*E1*1' ], ...meta } ],
                                  chargingTariffOffers: [ { '@id': 'gdf-offer', name: { en: 'Five off' }, discount: { percent: 5 }, EVSEGroupIds: [ 'DE*GDF*EG_FAV' ], ...meta } ],
                                  ...meta } ],
            gridOperators:    [ { '@id': 'DE*NET', name: { en: 'Net' },
                                  gridConnectionPoints: [ { '@id': 'gcp-1', name: { en: 'Connection 1' }, voltageLevel: 'LowVoltage',
                                                            maintainedBy: { entityType: 'ChargingStationOperator', entityId: 'DE*GEF' },
                                                            energyMeter: { '@id': 'gcp-meter-1', ...meta }, nominalVoltage: 400 } ],
                                  energyMeterGroups: [ { '@id': 'net-meters', name: { en: 'Net meters' }, energyMeterIds: [ 'gcp-meter-1' ], ...meta } ],
                                  energyMeterTemplates: [ { '@id': 'net-meter-template', name: { en: 'Grid meter' }, role: 'grid', ...meta } ],
                                  ...meta } ],
            parkingOperators: [ { '@id': 'DE*PRK', name: { en: 'Parking' },
                                  parkingGarages: [ { '@id': 'garage-1', name: { en: 'Garage' }, chargingStationIds: [ 'DE*GEF*S1' ], parkingProductIds: [ 'P1' ], ...meta } ],
                                  parkingSpaces: [ { '@id': 'space-1', parkingGarageId: 'garage-1', parkingSensorIds: [ 'sensor-1' ], length: 5, width: 2.5, ...meta } ],
                                  parkingSensors: [ { '@id': 'sensor-1', ...meta } ],
                                  parkingSpaceTemplates: [ { '@id': 'space-template-1', ...meta } ],
                                  parkingSpaceGroups: [ { '@id': 'space-group-1', parkingSpaceIds: [ 'space-1' ], ...meta } ],
                                  parkingProducts: [ { '@id': 'P1', minDuration: 0, stopParkingAfterTime: 3600 } ],
                                  ...meta } ],
        };
        change(parts);
        return [ { op: 'add', path: `${gefAt}/chargingPoolTemplates`,   value: parts.poolTemplates },
                 { op: 'add', path: `${gefAt}/chargingTariffTemplates`, value: parts.tariffTemplates },
                 { op: 'add', path: `${gefAt}/chargingTariffGroups`,    value: parts.tariffGroups },
                 { op: 'add', path: `${gefAt}/chargingPoolGroups`,      value: parts.poolGroups },
                 { op: 'add', path: `${gefAt}/chargingTariffOffers`,    value: parts.offers },
                 { op: 'add', path: `${gefAt}/brands`,                  value: parts.brands },
                 { op: 'add', path: `${gefAt}/parkingSpaces`,           value: parts.parkingSpaces },
                 { op: 'add', path: `${pool1}/gridConnectionPointId`,   value: 'gcp-1' },
                 { op: 'add', path: '/eMobilityProviders',              value: parts.providers },
                 { op: 'add', path: '/gridOperators',                   value: parts.gridOperators },
                 { op: 'add', path: '/parkingOperators',                value: parts.parkingOperators } ];
    };

    const version = (id, basis, description, reason, patch, rich) =>
        refuse({ id, kind: 'version', basis, description: rich === undefined ? description : `${description} (QA with an entity of every kind WWCP_POI3 reads)`, reason,
                 document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, ...(rich ?? []), ...patch ]) });

    // ---- Of the roaming network and its operator.
    version('version-read-name-not-an-object',    doc('RoamingNetwork'), 'The name of the roaming network is the number 5, not a text in languages.',
            "JSON property 'name' is not an object!",                                            [ { op: 'replace', path: '/name', value: 5 } ]);
    version('version-read-created-missing',       doc('RoamingNetwork'), 'The roaming network without the timestamp of its creation.',
            `The creation timestamp 'created' of '${qa['@id']}' is missing!`,                    [ { op: 'remove', path: '/created' } ]);
    version('version-read-created-number',        doc('RoamingNetwork'), 'The roaming network created at the number 5.',
            "Invalid creation timestamp '5'!",                                                   [ { op: 'replace', path: '/created', value: 5 } ]);
    version('version-read-data-license-unknown',  doc('RoamingNetwork'), 'The roaming network names the data license XYZ by its identification alone, which is no well-known one.',
            "The data license 'XYZ' is not well-known, so it must be given completely!",         [ { op: 'add', path: '/dataLicenseIds', value: [ 'XYZ' ] } ]);
    version('version-read-network-signing-keys',  doc('RoamingNetwork'), 'The roaming network names signing keys, as null: it has none of its own.',
            "A roaming network has no keys of its own: they are the keys of its operator, 'operator'!", [ { op: 'add', path: '/signingKeys', value: null } ]);
    version('version-read-operator-homepage',     doc('RoamingNetworkOperator'), 'The operator of the roaming network names the homepage https://x_y.org, of a host name with an underscore.',
            "Invalid homepage 'https://x_y.org'!",                                               [ { op: 'add', path: '/operator/homepage', value: 'https://x_y.org' } ]);

    // ---- Of the charging station operator, its pools, stations, EVSEs, connectors and energy meters.
    version('version-read-pools-not-an-array',    doc('ChargingStationOperator'), 'DE*GEF names its charging pools as the text x.',
            'The charging pools must be a JSON array!',                                         [ { op: 'replace', path: `${gefAt}/chargingPools`, value: 'x' } ]);
    version('version-read-logo-without-url',      doc('ChargingStationOperator'), 'DE*GEF names a logo without its URL.',
            'A logo requires an URI!',                                                           [ { op: 'add', path: `${gefAt}/logos`, value: [ {} ] } ]);
    version('version-read-latitude',              doc('ChargingPool'), 'DE*GEF*P1 lies at the latitude 91.',
            "Invalid geo location: Invalid 'latitude' value!",                                   [ { op: 'replace', path: `${pool1}/geoLocation/lat`, value: 91 } ]);
    version('version-read-address-without-street', doc('ChargingPool'), 'DE*GEF*P1 names an address without its street.',
            "Invalid address: Missing property 'street'!",                                       [ { op: 'add', path: `${pool1}/address`, value: { postalCode: '07745', city: { en: 'Jena' }, country: 'DE' } } ]);
    version('version-read-opening-times-reversed', doc('ChargingPool'), 'DE*GEF*P1 is open on Mondays from 20:00 to 08:00, a period ending before it begins.',
            "Invalid opening times: The end period '08:00h' must be after the start period '20:00h'!",
            [ { op: 'add', path: `${pool1}/openingTimes`, value: { regularOpenings: [ { monday: [ { begin: '20:00', end: '08:00' } ] } ] } } ]);
    version('version-read-image-without-type',    doc('ChargingPool'), 'DE*GEF*P1 names an image without its type.',
            `Invalid images '{"url":"https://example.org/p.png","category":"photo"}': Missing JSON property 'type'!`,
            [ { op: 'add', path: `${pool1}/images`, value: [ { url: 'https://example.org/p.png', category: 'photo' } ] } ]);
    version('version-read-authentication-mode-untrimmed', doc('ChargingPool'), "DE*GEF*P1 names the authentication mode ' RFID', with a space before it.",
            `Invalid authentication mode '{"type":" RFID"}': Invalid authentication mode: The type of an authentication mode must be a text without surrounding whitespace!`,
            [ { op: 'add', path: `${pool1}/authenticationModes`, value: [ { type: ' RFID' } ] } ]);
    version('version-read-energy-mix-percentage', doc('ChargingPool'), 'DE*GEF*P1 names an energy mix of 160 % wind.',
            'Invalid energy mix: energySources[0][1]: expected a percentage between 0 and 100!',
            [ { op: 'add', path: `${pool1}/energyMix`, value: { energySources: [ [ 'Wind', '160 %' ] ], environmentalImpacts: [], supplierName: { en: 'S' }, productName: { en: 'P' } } } ]);
    version('version-read-station-above-its-evses', doc('ChargingStation'), 'DE*GEF*S1 has a maximum power of 999999 W, its two EVSEs one of 1 W each.',
            "The given JSON representation of a charging station is invalid: The maximum power of the charging station 'DE*GEF*S1', 999999 W, must not exceed the 2 W of all its EVSEs together!",
            [ { op: 'add', path: `${stationS1}/maxPower`, value: 999999 }, { op: 'replace', path: `${evseE11}/maxPower`, value: 1 }, { op: 'replace', path: `${evseE12}/maxPower`, value: 1 } ]);
    version('version-read-current-type',          doc('EVSE'), 'DE*GEF*E1*1 names the current type dc, in lower case.',
            "Invalid current type 'dc'!",                                                        [ { op: 'replace', path: `${evseE11}/currentTypes`, value: [ 'dc' ] } ]);
    version('version-read-energy-meter-not-an-object', doc('EVSE'), 'DE*GEF*E1*1 names its energy meter as the text x.',
            'The energy meter must be a JSON object!',                                          [ { op: 'replace', path: `${evseE11}/energyMeter`, value: 'x' } ]);
    version('version-read-connector-format',      doc('EVSETemplate'), 'The charging connector of DE*GEF*ET_AC is of the format socket, in lower case.',
            "Invalid charging connector format 'socket'!",                                       [ { op: 'replace', path: `${templateAt}/chargingConnectors/0/format`, value: 'socket' } ]);
    version('version-read-socket-with-cable',     doc('EVSETemplate'), 'The charging connector of DE*GEF*ET_AC, a socket, names a cable length of 2 m.',
            "The charging connector '1' is a socket: it has no cable of its own!",               [ { op: 'add', path: `${templateAt}/chargingConnectors/0/cableLength`, value: 2 } ]);
    version('version-read-meter-role',            doc('EnergyMeterTemplate'), 'DE*GEF*EMT_AC names its role as the number 5.',
            "Invalid energy meter role '5'!",                                                    [ { op: 'replace', path: `${emtAC}/role`, value: 5 } ]);
    version('version-read-legal-status',          doc('EnergyMeterTemplate'), `DE*GEF*EMT_DC names the legal status of its transparency software ${status.transparencySoftwareId} as the number 5.`,
            `Invalid transparency software status '${JSON.stringify({ ...status, legalStatus: 5 })}': Invalid legal status '5'!`,
            [ { op: 'replace', path: `${emtDC}/transparencySoftwareStatus/0/legalStatus`, value: 5 } ]);

    // ---- Of identifications, as their types read them.
    version('version-read-tariff-id-lowercase',   `${SPEC}, 2`, 'The charging tariff DE*GEF*T_AC identified in lower case, de*gef*t_ac.',
            "Invalid 'charging tariff identification'!",                                         [ { op: 'replace', path: `${tariffAt}/@id`, value: 'de*gef*t_ac' } ]);
    version('version-read-pool-without-id',       doc('ChargingPool'), 'DE*GEF*P1 without its identification.',
            "Missing JSON property '@id'!",                                                      [ { op: 'remove', path: `${pool1}/@id` } ]);
    version('version-read-group-member-id',       doc('EVSEGroup'), 'The EVSE group DE*GEF*EG_AC names its member DE*GEF*E2*1 in lower case, de*gef*e2*1.',
            "Invalid member identification 'de*gef*e2*1'!",                                      [ { op: 'replace', path: `${groupAC}/EVSEIds`, value: [ 'de*gef*e2*1' ] } ]);
    version('version-read-template-id',           doc('ChargingStation'), 'DE*GEF*S1 names its template DE*GEF*ST_DC in lower case, de*gef*st_dc.',
            "Invalid template identification 'de*gef*st_dc'!",                                   [ { op: 'replace', path: `${stationS1}/templateIds`, value: [ 'de*gef*st_dc' ] } ]);
    version('version-read-provider-id',           doc('EMobilityProvider'), 'The e-mobility provider identified as DE-GDFX, a provider identification of four characters.',
            "Invalid 'e-mobility provider identification'!",                                     [], richer(parts => { parts.providers[0]['@id'] = 'DE-GDFX'; }));

    // ---- Of charging tariffs, their elements, templates and offers.
    version('version-read-tariff-currency',       doc('ChargingTariff'), 'DE*GEF*T_AC in the currency eur, in lower case.',
            "The currency of the charging tariff 'DE*GEF*T_AC' must be an ISO 4217 code, not 'eur'!", [ { op: 'replace', path: `${tariffAt}/currency`, value: 'eur' } ]);
    version('version-read-price-component-without-type', doc('ChargingTariff'), 'The price component of DE*GEF*T_AC without its type.',
            'A price component needs its type!',                                                 [ { op: 'remove', path: `${component}/type` } ]);
    version('version-read-price-component-without-price', doc('ChargingTariff'), 'The price component of DE*GEF*T_AC without its price.',
            "Missing JSON property 'price'!",                                                    [ { op: 'remove', path: `${component}/price` } ]);
    version('version-read-price-component-step-size-text', doc('ChargingTariff'), 'The price component of DE*GEF*T_AC of the step size x, a text.',
            "Invalid value for 'step size'!",                                                    [ { op: 'replace', path: `${component}/stepSize`, value: 'x' } ]);
    version('version-read-price-component-vat',   doc('ChargingTariff'), 'The price component of DE*GEF*T_AC with a VAT of 120 percent.',
            'The VAT of an ENERGY price component must be between 0 and 100 percent!',          [ { op: 'add', path: `${component}/vat`, value: 120 } ]);
    version('version-read-price-component-without-step-size', doc('ChargingTariff'), 'The price component of DE*GEF*T_AC, of energy, without its step size.',
            'An ENERGY price component needs a positive step size!',                            [ { op: 'remove', path: `${component}/stepSize` } ]);
    version('version-read-restriction-start-time', doc('ChargingTariff'), 'The element of DE*GEF*T_AC restricted to the start time 9:00, of one digit of its hour.',
            "Invalid startTime '9:00', expected HH:mm!",                                         [ { op: 'add', path: `${tariffAt}/elements/0/restrictions`, value: { startTime: '9:00' } } ]);
    version('version-read-restriction-power-reversed', doc('ChargingTariff'), 'The element of DE*GEF*T_AC restricted to a minimum power of 50 and a maximum power of 10.',
            'Invalid charging tariff restrictions: The minimum power of a charging tariff restriction must not exceed its maximum!',
            [ { op: 'add', path: `${tariffAt}/elements/0/restrictions`, value: { minPower: 50, maxPower: 10 } } ]);
    version('version-read-offer-neither-price-nor-discount', doc('ChargingTariffOffer'), 'The offer offer-1 of DE*GEF without its discount, and without a price of its own.',
            "The given JSON representation of a charging tariff offer is invalid: The charging tariff offer 'offer-1' must have exactly one of a price of its own and a discount!",
            [], richer(parts => { delete parts.offers[0].discount; }));
    version('version-read-offer-price-without-currency', doc('ChargingTariffOffer'), 'The offer offer-1 of DE*GEF with a price of its own, a charging tariff without its currency, instead of its discount.',
            "The currency of the price of the charging tariff offer 'offer-1' must be an ISO 4217 code!",
            [], richer(parts => { delete parts.offers[0].discount; parts.offers[0].chargingTariff = { elements: [ { priceComponents: [ { type: 'FLAT', price: 1 } ] } ] }; }));
    version('version-read-discount-dimensions-empty', doc('ChargingTariffOffer'), 'The offer offer-1 of DE*GEF with a discount of 10 percent of no dimensions, an empty array.',
            'The dimensions of a discount must not be empty: without them, it reduces all of them!',
            [], richer(parts => { parts.offers[0].discount = { percent: 10, dimensions: [] }; }));

    // ---- Of the parties: manufacturers and their models, releases, e-mobility providers, grid and parking operators.
    version('version-read-manufacturer-homepage', doc('ChargingStationManufacturer'), 'GraphDefined, the manufacturer of charging stations, names its homepage as the number 5.',
            "Invalid homepage '5'!",                                                             [ { op: 'replace', path: `${gd}/homepage`, value: 5 } ]);
    version('version-read-model-evses-none',      doc('ChargingStationManufacturer'), 'The charging station model GD-AC44 of no EVSEs.',
            "The given JSON representation of a charging station model is invalid: The number of EVSEs of the charging station model 'GD-AC44' must be at least one!",
            [ { op: 'replace', path: `${gdAC44}/numberOfEVSEs`, value: 0 } ]);
    version('version-read-meter-model-accuracy-class', doc('EnergyMeterManufacturer'), "The energy meter model KDM-500 of the accuracy class ' 0.5S', with a space before it.",
            "The given JSON representation of an energy meter model is invalid: The accuracy class of the energy meter model 'KDM-500' must not be empty nor begin or end with whitespace!",
            [ { op: 'replace', path: `${kdm500}/accuracyClass`, value: ' 0.5S' } ]);
    version('version-read-cra-role',              doc('TransparencySoftwareManufacturer'), 'The manufacturer of the transparency software names its role under the Cyber Resilience Act as MANUFACTURER, in upper case.',
            "The role 'MANUFACTURER' under the Cyber Resilience Act must be one of manufacturer, openSourceSoftwareSteward!",
            [ { op: 'replace', path: `${tsm}/craRole`, value: 'MANUFACTURER' } ]);
    version('version-read-release-without-name',  doc('TransparencySoftwareManufacturer'), 'The release GraphDefined:chargy-1.5.0 without its name.',
            'TransparencySoftware: name: expected a multi-language object.',                     [ { op: 'remove', path: `${release}/name` } ]);
    version('version-read-release-repository-relative', doc('TransparencySoftwareManufacturer'), 'The release GraphDefined:chargy-1.5.0 names its source code repository as github.com/x, without its scheme.',
            'TransparencySoftware: sourceCodeRepository: expected an absolute URL.',             [ { op: 'replace', path: `${release}/sourceCodeRepository`, value: 'github.com/x' } ]);
    version('version-read-provider-group-of-another', doc('EMobilityProvider'), 'DE-GDF has the EVSE group DE*XYZ*EG_FAV, of another provider.',
            "The given JSON representation of an e-mobility provider is invalid: The group 'DE*XYZ*EG_FAV' does not belong to the e-mobility provider 'DE-GDF'!",
            [], richer(parts => { parts.providers[0].EVSEGroups[0]['@id'] = 'DE*XYZ*EG_FAV'; parts.providers[0].chargingTariffOffers[0].EVSEGroupIds = [ 'DE*XYZ*EG_FAV' ]; }));
    version('version-read-grid-connection-point-maintainer', doc('GridOperator'), 'The grid connection point gcp-1 of DE*NET maintained by DE*NET, a grid operator.',
            "The given JSON representation of a grid connection point is invalid: Besides its grid operator, the grid connection point 'gcp-1' can only be maintained by a charging station operator or a parking operator, not by the GridOperator 'DE*NET'!",
            [], richer(parts => { parts.gridOperators[0].gridConnectionPoints[0].maintainedBy = { entityType: 'GridOperator', entityId: 'DE*NET' }; }));
    version('version-read-meter-group-member-unknown', doc('GridOperator'), 'The energy meter group net-meters of DE*NET names the meter nope, which DE*NET does not have.',
            "The given JSON representation of a grid operator is invalid: The member 'nope' of the group 'net-meters' is unknown at the grid operator 'DE*NET'!",
            [], richer(parts => { parts.gridOperators[0].energyMeterGroups[0].energyMeterIds = [ 'nope' ]; }));
    version('version-read-garage-product-unknown', doc('ParkingOperator'), 'The parking garage garage-1 of DE*PRK names the parking product p1, which DE*PRK has as P1 only.',
            "The given JSON representation of a parking operator is invalid: The parking product 'p1' of the parking garage 'garage-1' is unknown at the parking operator 'DE*PRK'!",
            [], richer(parts => { parts.parkingOperators[0].parkingGarages[0].parkingProductIds = [ 'p1' ]; }));
    version('version-read-parking-space-length',  doc('ParkingSpace'), 'The parking space space-1 of DE*PRK of the length 0.',
            "The given JSON representation of a parking space is invalid: The length of the parking space 'space-1' must be positive!",
            [], richer(parts => { parts.parkingOperators[0].parkingSpaces[0].length = 0; }));
    version('version-read-brand-without-name',    doc('Brand'), 'The brand GEF-Brand of DE*GEF without its name.',
            "The brand 'GEF-Brand' needs its name!",                                            [], richer(parts => { delete parts.brands[0].name; }));

    // ---- Of the constructor of a charging station operator: its templates, tariffs, groups and offers.
    version('version-read-operator-tariff-unknown', doc('ChargingStationOperator'), 'DE*GEF without its charging tariffs, which its EVSE templates name.',
            ofOperator("The charging tariff 'DE*GEF*T_AC' of the template 'DE*GEF*ET_AC' is unknown at the operator 'DE*GEF'!"), [ { op: 'remove', path: `${gefAt}/chargingTariffs` } ]);
    version('version-read-operator-template-unknown', doc('ChargingStationOperator'), 'DE*GEF without its EVSE templates, which its EVSEs name.',
            ofOperator("The template 'DE*GEF*ET_DC' of the EVSE 'DE*GEF*E1*1' is unknown at the operator 'DE*GEF'!"), [ { op: 'remove', path: `${gefAt}/EVSETemplates` } ]);
    version('version-read-operator-group-member-unknown', doc('ChargingStationOperator'), 'DE*GEF without its charging pools, whose EVSEs its groups name.',
            ofOperator("The member 'DE*GEF*E2*1' of the group 'DE*GEF*EG_AC' is unknown at the operator 'DE*GEF'!"), [ { op: 'remove', path: `${gefAt}/chargingPools` } ]);
    version('version-read-tariff-without-currency', doc('ChargingTariff'), 'DE*GEF*T_AC without its currency, which no template gives it.',
            ofOperator("The charging tariff 'DE*GEF*T_AC' has no currency, neither of its own nor of its templates!"), [ { op: 'remove', path: `${tariffAt}/currency` } ]);
    version('version-read-tariff-min-above-template-max', doc('ChargingTariffTemplate'), 'DE*GEF*T_AC of the minimum price 5, of its template DE*GEF*TT_BASE of the maximum price 2.',
            ofOperator("The charging tariff 'DE*GEF*T_AC' with the properties of its templates 'DE*GEF*TT_BASE' is invalid: The minimum price of the charging tariff 'DE*GEF*T_AC' must not exceed its maximum price!"),
            [ { op: 'add', path: `${tariffAt}/templateIds`, value: [ 'DE*GEF*TT_BASE' ] }, { op: 'add', path: `${tariffAt}/minPrice`, value: { excludingVAT: 5 } } ],
            richer(parts => { parts.tariffTemplates[0].maxPrice = { excludingVAT: 2 }; }));
    version('version-read-offer-group-unknown',   doc('ChargingTariffOffer'), 'The offer offer-1 of DE*GEF for the EVSE group DE*GEF*EG_NONE, which DE*GEF does not have.',
            ofOperator("The EVSE group 'DE*GEF*EG_NONE' of the charging tariff offer 'offer-1' is unknown at the operator 'DE*GEF'!"),
            [], richer(parts => { parts.offers[0].EVSEGroupIds = [ 'DE*GEF*EG_NONE' ]; }));
    version('version-read-pool-group-of-another', doc('ChargingPoolGroup'), 'DE*GEF has the charging pool group DE*XYZ*PG_ALL, of another operator.',
            ofOperator("The group 'DE*XYZ*PG_ALL' does not belong to the operator 'DE*GEF'!"),  [], richer(parts => { parts.poolGroups[0]['@id'] = 'DE*XYZ*PG_ALL'; }));
    version('version-read-operator-parking-space-in-garage', doc('ParkingSpace'), 'The parking space gef-space-1 of DE*GEF in the parking garage garage-1: only a parking space of a parking operator is in one.',
            ofOperator("The parking space 'gef-space-1' of the operator 'DE*GEF' can be in no parking garage, and have no parking sensors or parking products: only those of a parking operator can!"),
            [], richer(parts => { parts.parkingSpaces[0].parkingGarageId = 'garage-1'; }));
    version('version-read-tariff-twice',          doc('ChargingTariff'), 'DE*GEF has DE*GEF*T_AC also as DE*GEF*T_A*C, the same identification but for a *.',
            ofOperator("The charging tariff 'DE*GEF*T_A*C' of the operator 'DE*GEF' must not be given twice!"),
            [ { op: 'add', path: `${gefAt}/chargingTariffs/-`, value: { ...at(qa, tariffAt), '@id': 'DE*GEF*T_A*C' } } ]);

    // ---- References the constructor of the roaming network checks.
    const REFS = doc('RoamingNetwork');
    version('version-ref-manufacturer-unknown',   REFS, 'The roaming network without its manufacturers of charging stations, which the station templates of DE*GEF name.',
            ofNetwork("The manufacturer 'GraphDefined' of the charging station template 'DE*GEF*ST_AC' is unknown in the roaming network!"), [ { op: 'remove', path: '/chargingStationManufacturers' } ]);
    version('version-ref-hardware-revision-without-model', REFS, 'The charging station template DE*GEF*ST_AC without its model, its hardware revision named.',
            ofNetwork("The hardware revision '1.0' of the charging station 'DE*GEF*S2' is named without its model!"), [ { op: 'remove', path: `${stAC}/modelId` } ]);
    version('version-ref-hardware-revision-of-no-model', REFS, 'The charging station model GD-AC44 without its hardware revisions, of which DE*GEF*ST_AC names 1.0.',
            ofNetwork("The hardware revision '1.0' of the charging station template 'DE*GEF*ST_AC' is no hardware revision of its model 'GD-AC44' of 'GraphDefined'!"), [ { op: 'remove', path: `${gdAC44}/hardwareRevisions` } ]);
    version('version-ref-evse-above-its-model',   REFS, 'DE*GEF*E1*1 of a maximum power of 999999 kW, its model GD-DC300 of 300 kW.',
            ofNetwork("The maximum power of the EVSE 'DE*GEF*E1*1', 999999 kW, is above the one of the model 'GD-DC300' of 'GraphDefined' of its charging station 'DE*GEF*S1', 300 kW!"),
            [ { op: 'replace', path: `${evseE11}/maxPower`, value: 999999000 } ]);
    version('version-ref-meter-template-model-without-manufacturer', REFS, 'The energy meter template DE*GEF*EMT_AC names its model SM-3 without its manufacturer.',
            ofNetwork("The energy meter template 'DE*GEF*EMT_AC' names the model 'SM-3' without its manufacturer!"), [ { op: 'remove', path: `${emtAC}/manufacturerId` } ]);
    version('version-ref-meter-hardware-revision-without-model', REFS, 'The energy meter template DE*GEF*EMT_AC without its model, its hardware revision named.',
            ofNetwork("The energy meter 'DE*GEF*M2*1' names the hardware revision '1.4' without its model!"), [ { op: 'remove', path: `${emtAC}/modelId` } ]);
    version('version-ref-meter-manufacturer-unknown', REFS, 'The roaming network without its manufacturers of energy meters, which a certificate names.',
            ofNetwork("The manufacturer 'KERNBERG' of the certificate 'PTB:2026-0017' is unknown in the roaming network!"), [ { op: 'remove', path: '/energyMeterManufacturers' } ]);
    version('version-ref-release-unknown',        REFS, 'The roaming network without its manufacturers of transparency software, whose release a certificate names.',
            ofNetwork("The transparency software release 'GraphDefined:chargy-1.5.0' of the certificate 'PTB:2026-0017' is unknown in the roaming network!"), [ { op: 'remove', path: '/transparencySoftwareManufacturers' } ]);
    version('version-ref-certificate-unknown',    REFS, 'The roaming network without its conformity assessment bodies, whose certificate DE*GEF*ST_DC names.',
            ofNetwork("The certificate 'PTB:2026-0042' of the charging station template 'DE*GEF*ST_DC' is unknown in the roaming network!"), [ { op: 'remove', path: '/conformityAssessmentBodies' } ]);
    version('version-ref-meter-not-of-the-certificate', REFS, 'The energy meter of DE*GEF*E1*1 without its template, so of no model the certificate of its station was issued with.',
            ofNetwork("The energy meter 'DE*GEF*M1*1' of the charging station 'DE*GEF*S1' is none of the energy meters the certificate 'PTB:2026-0042' was issued with!"), [ { op: 'remove', path: `${evseE11}/energyMeter/templateIds` } ]);
    version('version-ref-meter-with-station-certificate', REFS, 'The energy meter template DE*GEF*EMT_AC names the certificate PTB:2026-0042, of a charging station model.',
            ofNetwork("The certificate 'PTB:2026-0042' of the energy meter 'DE*GEF*M2*1' is for the charging station model 'GD-DC300' of 'GraphDefined', not for a model of energy meters!"),
            [ { op: 'add', path: `${emtAC}/certificateIds`, value: [ 'PTB:2026-0042' ] } ]);
    version('version-ref-meter-signature-method', REFS, 'The energy meter template DE*GEF*EMT_AC names the signature method EDL40, which its model SM-3 does not have.',
            ofNetwork("The energy meter 'DE*GEF*M2*1' signs with 'EDL40', no signature method of its model 'SM-3' of 'SAALE'!"), [ { op: 'replace', path: `${emtAC}/signatureMethods`, value: [ 'EDL40' ] } ]);
    version('version-ref-grid-connection-point-unknown', REFS, 'DE*GEF*P1 at the grid connection point gcp-9, which no grid operator has.',
            ofNetwork("The grid connection point 'gcp-9' of the charging pool 'DE*GEF*P1' is unknown in the roaming network!"),
            [ { op: 'add', path: `${pool1}/gridConnectionPointId`, value: 'gcp-9' } ], richer());
    version('version-ref-parking-space-unknown',  REFS, 'DE*GEF*S1 at the parking space space-9, which no party has.',
            ofNetwork("The parking space 'space-9' of the charging station 'DE*GEF*S1' is unknown in the roaming network!"),
            [ { op: 'add', path: `${stationS1}/parkingSpaceIds`, value: [ 'space-9' ] } ], richer());
    version('version-ref-garage-station-unknown', REFS, 'The parking garage garage-1 of DE*PRK names the charging station DE*GEF*S9, which DE*GEF does not have.',
            ofNetwork("The charging station 'DE*GEF*S9' of the parking garage 'garage-1' is unknown in the roaming network!"),
            [], richer(parts => { parts.parkingOperators[0].parkingGarages[0].chargingStationIds = [ 'DE*GEF*S9' ]; }));
    version('version-ref-maintainer-unknown',     REFS, 'The grid connection point gcp-1 maintained by the charging station operator DE*XYZ, which the roaming network does not have.',
            ofNetwork("The maintainer of the grid connection point 'gcp-1', the ChargingStationOperator 'DE*XYZ', is unknown in the roaming network!"),
            [], richer(parts => { parts.gridOperators[0].gridConnectionPoints[0].maintainedBy = { entityType: 'ChargingStationOperator', entityId: 'DE*XYZ' }; }));
    version('version-ref-provider-twice',         REFS, 'The e-mobility provider DE-GDF given twice, the second time as DE*GDF.',
            ofNetwork("The e-mobility provider 'DE*GDF' must not be given twice!"),
            [], richer(parts => { parts.providers.push({ '@id': 'DE*GDF', name: { en: 'GDF2' }, created: qa.created, lastChange: qa.created }); }));
    const identityKey = at(qa, `${gd}/identityKeys/0`);
    version('version-ref-key-of-two-parties',     REFS, 'DE-GDF names the identity key of GraphDefined, the manufacturer of charging stations, as its own.',
            ofNetwork(`The key '${identityKey['@id']}' of the ChargingStationManufacturer 'GraphDefined' is a key of the EMobilityProvider 'DE-GDF' as well: a key belongs to one party only!`),
            [], richer(parts => { parts.providers[0].identityKeys = [ identityKey ]; }));

    // ---- Values WWCP_POI3 writes otherwise than given (2, Written forms), in the words of `notHeld`.
    version('version-held-last-change-missing',   HELD, 'DE*GEF*P2 without its lastChange, which WWCP_POI3 writes of its own: the timestamp of its creation.',
            notHeld(`${pool2}/lastChange`, holds(JSON.stringify(at(qa, `${pool2}/created`)))), [ { op: 'remove', path: `${pool2}/lastChange` } ]);
    version('version-held-party-name-missing',    HELD, 'GraphDefined, the manufacturer of charging stations, without its name, which WWCP_POI3 makes up of its own.',
            notHeld(`${gd}/name`, holds(`{"en":"Charging Station Manufacturer 'GraphDefined'"}`)), [ { op: 'remove', path: `${gd}/name` } ]);
    version('version-held-name-empty',            HELD, 'DE*GEF*P1 names its name as a text in no language, which WWCP_POI3 leaves out.',
            notHeld(`${pool1}/name`, LEAVES),                                                    [ { op: 'replace', path: `${pool1}/name`, value: {} } ]);
    version('version-held-license-urls-missing',  HELD, 'The open source license of GraphDefined:chargy-1.5.0 without its URLs, which WWCP_POI3 writes also empty.',
            notHeld(`${release}/openSourceLicenses/0/URLs`, holds('[]')),                       [ { op: 'remove', path: `${release}/openSourceLicenses/0/URLs` } ]);
    version('version-held-id-number',             HELD, 'BSI identified by the number 5, which WWCP_POI3 writes as a text.',
            notHeld(`${bsi}/@id`, holds('"5"')),                                                 [ { op: 'replace', path: `${bsi}/@id`, value: 5 } ]);
    version('version-held-connector-type-number', HELD, 'The charging connector of DE*GEF*ET_AC of the type 5, which WWCP_POI3 writes as a text.',
            notHeld(`${templateAt}/chargingConnectors/0/type`, holds('"5"')),                   [ { op: 'replace', path: `${templateAt}/chargingConnectors/0/type`, value: 5 } ]);
    version('version-held-property-unknown',      HELD, 'DE*GEF*P2 names the property colour, which WWCP_POI3 does not write.',
            notHeld(`${pool2}/colour`, LEAVES),                                                  [ { op: 'add', path: `${pool2}/colour`, value: 'green' } ]);
    version('version-held-restriction-unknown',   HELD, 'The element of DE*GEF*T_AC from 08:00 and to a state of charge of at most 80 %, maxStateOfCharge, a restriction no charging tariff has: a reader not knowing it would price every session from 08:00 so (D18).',
            notHeld(`${tariffAt}/elements/0/restrictions/maxStateOfCharge`, LEAVES),            [ { op: 'add', path: `${tariffAt}/elements/0/restrictions`, value: { startTime: '08:00', maxStateOfCharge: 80 } } ]);
    version('version-held-key-statement-property', HELD, 'The key statement of the operator of the roaming network names the property x, which WWCP_POI3 does not write.',
            notHeld('/operator/keyStatement/x', LEAVES),                                         [ { op: 'add', path: '/operator/keyStatement/x', value: 1 } ]);
    version('version-held-data-license-of-a-view', HELD, 'DE*GEF*P2 names the data license ODbL by its identification alone, as a view does: a version names it completely.',
            notHeld(`${pool2}/dataLicenseIds`, LEAVES),                                          [ { op: 'add', path: `${pool2}/dataLicenseIds`, value: [ 'ODbL' ] } ]);
    version('version-held-release-property',      HELD, 'The release GraphDefined:chargy-1.5.0 names the property x, which a release does not have.',
            "TransparencySoftware: Unknown property 'x'.",                                       [ { op: 'add', path: `${release}/x`, value: 1 } ]);
    version('version-held-operator-id-lowercase', HELD, 'DE*GEF identified in lower case, de*gef, which WWCP_POI3 writes in upper case.',
            notHeld(`${gefAt}/@id`, holds('"DE*GEF"')),                                          [ { op: 'replace', path: `${gefAt}/@id`, value: 'de*gef' } ]);
    version('version-held-homepage-without-scheme', HELD, 'GraphDefined names its homepage without its scheme, which WWCP_POI3 writes with https://.',
            notHeld(`${gd}/homepage`, holds(JSON.stringify(at(qa, `${gd}/homepage`)))),        [ { op: 'replace', path: `${gd}/homepage`, value: at(qa, `${gd}/homepage`).replace('https://', '') } ]);
    version('version-held-meter-role-upper-case', HELD, 'DE*GEF*EMT_AC names its role as EVSE, in upper case, which WWCP_POI3 writes as evse.',
            notHeld(`${emtAC}/role`, holds('"evse"')),                                          [ { op: 'replace', path: `${emtAC}/role`, value: 'EVSE' } ]);
    version('version-held-signature-method-lower-case', HELD, 'The energy meter model KDM-500 names its signature method as ocmf, in lower case, which WWCP_POI3 writes as OCMF.',
            notHeld(`${kdm500}/signatureMethods/0`, holds('"OCMF"')),                           [ { op: 'replace', path: `${kdm500}/signatureMethods`, value: [ 'ocmf' ] } ]);
    version('version-held-currency-untrimmed',    HELD, "DE*GEF*T_AC in the currency 'EUR ', with a space after it, which WWCP_POI3 writes trimmed.",
            notHeld(`${tariffAt}/currency`, holds('"EUR"')),                                    [ { op: 'replace', path: `${tariffAt}/currency`, value: 'EUR ' } ]);
    version('version-held-provider-without-name', HELD, 'The e-mobility provider DE-GDF without its name, which WWCP_POI3 makes up of its own.',
            notHeld('/eMobilityProviders/0/name', holds(`{"en":"E-Mobility Provider 'DE-GDF'"}`)),
            [ { op: 'add', path: '/eMobilityProviders', value: [ { '@id': 'DE-GDF', created: qa.created, lastChange: qa.created } ] } ]);

    // A number, a boolean or a text given as another JSON type WWCP_POI3 reads, which it writes as its own.
    version('version-held-max-power-text',        HELD, "DE*GEF*E1*1 names its maximum power as the text ' 150000 ', which WWCP_POI3 reads and writes as the number 150000.",
            notHeld(`${evseE11}/maxPower`, holds('150000')),                                    [ { op: 'replace', path: `${evseE11}/maxPower`, value: ' 150000 ' } ]);
    version('version-held-nominal-voltage-text',  HELD, 'The grid connection point gcp-1 names its nominal voltage as the text 400, which WWCP_POI3 writes as a number.',
            notHeld('/gridOperators/0/gridConnectionPoints/0/nominalVoltage', holds('400')),
            [], richer(parts => { parts.gridOperators[0].gridConnectionPoints[0].nominalVoltage = '400'; }));
    version('version-held-boolean-text',          HELD, 'DE*GEF*P1 names whether it can be charged at when closed as the text TRUE, which WWCP_POI3 writes as true.',
            notHeld(`${pool1}/chargingWhenClosed`, holds('true')),                              [ { op: 'add', path: `${pool1}/chargingWhenClosed`, value: 'TRUE' } ]);
    version('version-held-boolean-number',        HELD, 'The charging connector of DE*GEF*ET_AC names whether it is lockable as the number 0, which WWCP_POI3 writes as false.',
            notHeld(`${templateAt}/chargingConnectors/0/lockable`, holds('false')),             [ { op: 'add', path: `${templateAt}/chargingConnectors/0/lockable`, value: 0 } ]);
    version('version-held-text-number',           HELD, 'The roaming network names its data source as the number 5, which WWCP_POI3 writes as a text.',
            notHeld('/dataSource', holds('"5"')),                                                [ { op: 'add', path: '/dataSource', value: 5 } ]);
    version('version-held-image-height-text',     HELD, 'DE*GEF*P1 names an image of the height +5, a text, which WWCP_POI3 writes as the number 5.',
            notHeld(`${pool1}/images/0/height`, holds('5')),
            [ { op: 'add', path: `${pool1}/images`, value: [ { url: 'https://example.com/a.png', category: 'photo', type: 'image/png', height: '+5' } ] } ]);
    version('version-held-duration-text',         HELD, 'DE*GEF*E1*1 names its maximum reservation duration as the text 600.0, which WWCP_POI3 writes as the number 600.',
            notHeld(`${evseE11}/maxReservationDuration`, holds('600')),                         [ { op: 'add', path: `${evseE11}/maxReservationDuration`, value: '600.0' } ]);

    // Opening times as Styx writes them: 24/7 always, hours of two digits, periods UTC.
    const openingAt = `${dottedOf(pool1)}.openingTimes`;
    const opening   = (id, description, reason, openingTimes) =>
        version(id, HELD, `DE*GEF*P1 is open ${description}.`, reason, [ { op: 'add', path: `${pool1}/openingTimes`, value: openingTimes } ]);
    const monday    = (begin) => [ { monday: [ { begin, end: '20:00' } ] } ];
    opening('version-held-opening-times-without-24-7', 'on Mondays from 08:00 to 20:00, not saying whether it is open 24/7, which Styx writes always',
            notHeldAt(`${openingAt}.24/7`, holds('false')),                                     { regularOpenings: monday('08:00') });
    opening('version-held-opening-times-empty',   'by regular openings given as an empty array, 24/7, which Styx leaves out',
            notHeldAt(`${openingAt}.regularOpenings`, 'a list without elements is left out'),  { '24/7': true, regularOpenings: [] });
    opening('version-held-opening-hour-one-digit', 'on Mondays from 8:00, of one digit of its hour, which Styx writes as 08:00',
            notHeldAt(`${openingAt}.regularOpenings[0].monday[0].begin`, holds('"08:00"')),    { '24/7': false, regularOpenings: monday('8:00') });
    opening('version-held-closing-offset',        '24/7 but for an exceptional closing beginning at a time with the offset +01:00, which Styx writes UTC',
            notHeldAt(`${openingAt}.exceptionalClosings[0]`, holds('"2026-12-23T23:00:00.000Z -> 2026-12-25T00:00:00.000Z"')),
            { '24/7': true, exceptionalClosings: [ '2026-12-24T00:00:00+01:00 -> 2026-12-25T00:00:00.000Z' ] });

    // NUTS codes in upper case and their ordinal order; an address with its country by its alpha-3 code.
    version('version-held-nuts-lower-case',       HELD, 'DE*GEF*P1 names the NUTS code de1, in lower case, which WWCP_POI3 writes in upper case.',
            notHeld(`${pool1}/nutsCodes/0`, holds('"DE1"')),                                    [ { op: 'add', path: `${pool1}/nutsCodes`, value: [ 'de1' ] } ]);
    version('version-held-nuts-out-of-order',     HELD, 'DE*GEF*P1 names the NUTS codes DE1 and AT1, in this order, not their ordinal one.',
            notHeld(`${pool1}/nutsCodes`, ORDER),                                                [ { op: 'add', path: `${pool1}/nutsCodes`, value: [ 'DE1', 'AT1' ] } ]);
    const address   = (id, description, reason, more) =>
        version(id, HELD, `DE*GEF*P1 has an address ${description}.`, reason,
                [ { op: 'add', path: `${pool1}/address`, value: { street: 'Main', postalCode: '07745', city: { en: 'Jena' }, country: 'DEU', ...more } } ]);
    address('version-held-country-alpha-2',       'in the country DE, by its alpha-2 code, which Styx writes by its alpha-3 code DEU',
            notHeld(`${pool1}/address/country`, holds('"DEU"')),                                { country: 'DE' });
    address('version-read-country-unknown',       'in the country XYZ, which is none',
            "Invalid address: Invalid 'country'!",                                               { country: 'XYZ' });
    address('version-held-street-untrimmed',      "of the street ' Main ', with spaces around it, which Styx writes trimmed",
            notHeld(`${pool1}/address/street`, holds('"Main"')),                                { street: ' Main ' });
    address('version-held-official-language-upper-case', 'of the official language DE, in upper case, which Styx writes in lower case',
            notHeld(`${pool1}/address/officialLanguages/0`, holds('"de"')),                     { officialLanguages: [ 'DE' ] });
    address('version-held-address-property-unknown', 'naming the property x, which Styx does not write',
            notHeld(`${pool1}/address/x`, LEAVES),                                               { x: 1 });

    // ---- Charging tariff offers of an operator must not overlap (9.4): covering one EVSE, for some of the same sessions,
    //      at some of the same times in the time zone of the EVSE's charging pool.
    const OFFERS   = `${SPEC}, 9.4`;
    quoted(SPEC, '**No overlap.** Two offers of one owner overlap where they cover the same EVSE, for sessions both apply', 'when two offers of one owner overlap');
    const WHERE    = [ 'EVSEGroupIds', 'chargingStationGroupIds', 'chargingPoolGroupIds', 'chargingStationOperatorIds' ];
    const offer    = (id, more = {}) => ({ '@id': id, name: { en: id }, discount: { percent: 10 }, ...(WHERE.some(property => property in more) ? {} : { EVSEGroupIds: [ 'DE*GEF*EG_AC' ] }), ...more, ...meta });
    const weekly   = (day, begin, end) => ({ '24/7': false, regularOpenings: [ { [day]: [ { begin, end } ] } ] });
    const overlap  = (first, second, evse = 'DE*GEF*E2*1') =>
        ofOperator(`The charging tariff offers '${first}' and '${second}' of the operator 'DE*GEF' overlap at the EVSE '${evse}': they must not cover the same EVSE for the same sessions at the same times!`);
    const offering = (id, description, reason, offers, timeZone) =>
        version(id, OFFERS, `DE*GEF offers ${description}.`, reason,
                timeZone === undefined ? [] : pools.map(pool => ({ op: 'add', path: `${pool}/timeZone`, value: timeZone })), richer(parts => { parts.offers = offers; }));

    offering('version-offers-overlap',            'a and b, both of a discount of 10 percent at its AC EVSEs, at all times',
             overlap('a', 'b'),                    [ offer('a'), offer('b') ]);
    offering('version-offers-overlap-by-operator', 'a at its DC EVSEs and b at all of its EVSEs, by the operator: they overlap at the first DC EVSE in the ordinal order',
             overlap('a', 'b', 'DE*GEF*E1*1'),    [ offer('a', { EVSEGroupIds: [ 'DE*GEF*EG_DC' ] }), offer('b', { chargingStationOperatorIds: [ 'DE*GEF' ] }) ]);
    offering('version-offers-overlap-by-pool-group', 'a at its AC EVSEs and b at the charging pools of the group DE*GEF*PG_ALL, DE*GEF*P1 with its AC EVSEs among them',
             overlap('a', 'b'),                    [ offer('a'), offer('b', { chargingPoolGroupIds: [ 'DE*GEF*PG_ALL' ] }) ]);
    offering('version-offers-overlap-ordinal',    'z, B and a at its AC EVSEs: the first pair in the ordinal order of the offers is B and a',
             overlap('B', 'a'),                    [ offer('z'), offer('B'), offer('a') ]);
    offering('version-offers-overlap-sessions',   'a for ad hoc sessions and b for all sessions',
             overlap('a', 'b'),                    [ offer('a', { sessions: 'adHoc' }), offer('b') ]);
    offering('version-offers-overlap-providers',  'a for contracts of DE-ABC and DE-GDF and b for contracts of DE*GDF, the same provider in another spelling',
             overlap('a', 'b'),                    [ offer('a', { sessions: 'contract', eMobilityProviderIds: [ 'DE-ABC', 'DE-GDF' ] }), offer('b', { sessions: 'contract', eMobilityProviderIds: [ 'DE*GDF' ] }) ]);
    offering('version-offers-overlap-validity',   'a until 2026-11-01T00:00:00.000Z and b from it: both inclusive',
             overlap('a', 'b'),                    [ offer('a', { notAfter: '2026-11-01T00:00:00.000Z' }), offer('b', { notBefore: '2026-11-01T00:00:00.000Z' }) ]);
    offering('version-offers-overlap-opening-times', 'a on Mondays from 08:00 to 12:00 and b from 11:59 to 13:00',
             overlap('a', 'b'),                    [ offer('a', { openingTimes: weekly('monday', '08:00', '12:00') }), offer('b', { openingTimes: weekly('monday', '11:59', '13:00') }) ]);
    offering('version-offers-overlap-time-zone',  'a on Monday, 2 November 2026, from 06:00 to 06:59:59.999 UTC and b on Mondays from 07:30 to 09:00, its charging pools in the time zone Europe/Berlin, where a is from 07:00 to 08:00',
             overlap('a', 'b'),                    [ offer('a', { notBefore: '2026-11-02T06:00:00.000Z', notAfter: '2026-11-02T06:59:59.999Z' }), offer('b', { openingTimes: weekly('monday', '07:30', '09:00') }) ], 'Europe/Berlin');
    offering('version-offers-overlap-daylight-saving', 'a on 29 March 2026 from 01:00 to 01:10 UTC, 03:00 to 03:10 in Berlin, and b on Sundays from 02:15 to 03:05, its charging pools in the time zone Europe/Berlin, which skips 02:00 to 03:00 that day: a local time it skips is the first one after it',
             overlap('a', 'b'),                    [ offer('a', { notBefore: '2026-03-29T01:00:00.000Z', notAfter: '2026-03-29T01:10:00.000Z' }), offer('b', { openingTimes: weekly('sunday', '02:15', '03:05') }) ], 'Europe/Berlin');
    offering('version-offers-overlap-exceptional-closing', 'a 24/7 but for an exceptional closing from 1 to 2 November 2026, and b from 1 November 2026 to 2 November 2026, 00:00, both inclusive: the end of the closing',
             overlap('a', 'b'),                    [ offer('a', { openingTimes: { '24/7': true, exceptionalClosings: [ '2026-11-01T00:00:00.000Z -> 2026-11-02T00:00:00.000Z' ] } }),
                                                     offer('b', { notBefore: '2026-11-01T00:00:00.000Z', notAfter: '2026-11-02T00:00:00.000Z' }) ]);

    // ---- The time zone of a charging pool or charging pool template (9.4): one of a region of the IANA time zone
    //      database, as it writes it, which the reader knows - refused otherwise, not taken as UTC. Only names every
    //      platform of both harnesses refuses alike: none a database of one knows and of another not, e.g.
    //      America/Ciudad_Juarez, which .NET on Windows does not find. WWCP_POI.TS took them all before `9cc620a` (D17, fixed).
    quoted(SPEC, '**Time zones.** The `timeZone` of a charging pool or of a charging pool template is a time zone of the IANA', 'which time zones a charging pool names');
    const zoned = (id, description, owner, timeZone, path, rich) =>
        refuse({ id, kind: 'version', basis: OFFERS,
                 description: rich === undefined ? `${description}.` : `${description}. (QA with an entity of every kind WWCP_POI3 reads)`,
                 reason: `The time zone '${timeZone}' of ${owner} is no time zone of a region of the IANA time zone database this reader knows!`,
                 document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, ...(rich ?? []), { op: 'add', path, value: timeZone } ]) });
    const poolZoned = (id, description, timeZone) =>
        zoned(id, `DE*GEF*P1 in the time zone ${timeZone}, ${description}`, "the charging pool 'DE*GEF*P1'", timeZone, `${pool1}/timeZone`);

    poolZoned('version-time-zone-abbreviation',       'an abbreviation without a region, which .NET finds on Linux and not on Windows',   'CET');
    poolZoned('version-time-zone-utc',                'without a region: a charging pool without a time zone is in UTC',                  'UTC');
    poolZoned('version-time-zone-etc',                'of the area Etc of the database, no region of it',                                  'Etc/GMT-1');
    poolZoned('version-time-zone-backward',           'an older name of the database outside its regions',                                 'US/Eastern');
    poolZoned('version-time-zone-windows',            'the name of Windows for Europe/Berlin',                                             'W. Europe Standard Time');
    poolZoned('version-time-zone-lower-case',         'Europe/Berlin in lower case, which .NET finds on Windows, as Europe/Berlin',         'europe/berlin');
    poolZoned('version-time-zone-place-upper-case',   'Europe/Berlin with its place in upper case',                                        'Europe/BERLIN');
    poolZoned('version-time-zone-unknown',            'of the region Europe, a place the database does not know',                          'Europe/Atlantis');
    poolZoned('version-time-zone-region-unknown',     'of a region the database does not have',                                            'Mars/Olympus');
    zoned('version-time-zone-template', 'The charging pool template DE*GEF*PT_STD in the time zone CET, an abbreviation without a region',
          "the charging pool template 'DE*GEF*PT_STD'", 'CET', `${gefAt}/chargingPoolTemplates/0/timeZone`, richer());

    // ---- The public keys of energy meters: a DER encoded SubjectPublicKeyInfo of a key BouncyCastle makes, identified by
    //      its SHA-256, its certificates DER encoded, the first of the key, each one issued by the next one. Those of the
    //      tests of WWCP_POI.TS, made by BouncyCastle 2.7.0, checked here with node:crypto.
    const KEYS     = doc('EnergyMeter');
    const KEYS_TS  = 'libs/WWCP_POI.TS/tests/measurementPublicKey.test.ts';
    quoted(SPEC, '`publicKeys` (`{@id, key, certificateChain?}`, the DER encoded SubjectPublicKeyInfo, identified by its', 'how an energy meter names its public keys');
    const SPKI     = 'A measurement public key must be a SubjectPublicKeyInfo: ';
    const b64      = (bytes) => Buffer.from(bytes).toString('base64');
    const fromTS   = (name, base64) => quoted(KEYS_TS, `${name}'${base64}'`, `the ${name.trim() || 'certificate'} of BouncyCastle`) && Buffer.from(base64, 'base64');
    const qaKey    = Buffer.from(at(qa, `${meterKey}/key`), 'base64');
    const rsa      = fromTS('rsa:     ', 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm6wivJCf0zESTY9v9RIe97vL+cyGGPzSPxxQ6OQsbS58/cxDAH/8rLKgjXuol7mETODYO9wXqd72amyRIofXglW7cYaThXvhsPwY3svY7kXHHh0hW9qmrFN39blcNrlgUl2dS9G2TjIo7OMU6t2OpMaOE0LR9F3wNAOkvfVFRNuMFezvxJSfXyvQ/f8wVLbXBINxhXgr8sC7Gen5ksbjEQ5aAJ9b8UaLCPFDZ3A0cM4tgUDD7A7Wib4qqUgx47Lq2PjtyaodifCgcILDfnSo8iKma1+wxx5JPkuWDW67py37/qaxPcyPXag+Qy8hAfVHKs8DsBJMJAwD+v0/aIOhswIDAQAB');
    const meter    = fromTS('meter:   ', 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg6ro/u9xb4/gjYr7/C2UYyJGq41tJLNNZwBkRF4dNJYioh6GCHFgl7N8kRkTalPircRJ53dn2G94kUnDzaLN3w==');
    const chain    = [ fromTS('    ', 'MIIBNDCBu6ADAgECAgMBwv0wCgYIKoZIzj0EAwMwFDESMBAGA1UEAwwJQXV0aG9yaXR5MB4XDTI2MTEwMjAwMDAwMFoXDTMxMTEwMzAwMDAwMFowEjEQMA4GA1UEAwwHbWV0ZXItMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIOq6P7vcW+P4I2K+/wtlGMiRquNbSSzTWcAZEReHTSWIqIehghxYJezfJEZE2pT4q3ESed3Z9hveJFJw82izd8wCgYIKoZIzj0EAwMDaAAwZQIwRayE1ArFO1XjIkXbGlWt8XoZFm4yeE1djLDxMJ+qWyf6pnjCgj16uSLpmFkh8FV1AjEA4qhgtAWHB8bsZ+mSKEYKcvNqbrV6CBUzV9B/BXYEKwAQblblmmk/gO3CG44Eknp+'),
                       fromTS('    ', 'MIIBaTCB76ADAgECAgMHif8wCgYIKoZIzj0EAwMwFDESMBAGA1UEAwwJQXV0aG9yaXR5MB4XDTI2MTEwMjAwMDAwMFoXDTMxMTEwMzAwMDAwMFowFDESMBAGA1UEAwwJQXV0aG9yaXR5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAErUe8U7o8VAfguQLI6SKb4yM9ZsFI6nfgpaUh3EiCUuPnYO0nxiSGWNey5yPycxHC78fPauLIh9MXwtlv3aJFg/a9DCO326dHEOLgX2RiMn/ckygkR/3sti3Jp8ZvRnBpoxMwETAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA2kAMGYCMQCN+WzAHTqV5iSkLydyxBlsn0hruh2VY7gfsdeFj57d5oLIrOkAolBvD9qJsKAtpqoCMQDYMQYa7Bb/DKFyNgrQFFOghaXJGBqoL0Ek5gQfYFWlx1B+6hsvL1rYkmeYGzYDHDk=') ];

    // The keys as node:crypto reads them, the chain issued as it says: the meter key's certificate by the authority.
    const [ certificate, authority ] = chain.map(der => new X509Certificate(der));
    const spkiOf   = (key) => createPublicKey({ key, format: 'der', type: 'spki' }).export({ format: 'der', type: 'spki' });
    if (sha256(qaKey) !== at(qa, `${meterKey}/@id`) || qaKey.length !== 91 || qaKey[26] !== 0x04 || !spkiOf(qaKey).equals(qaKey))
        fail(`QA.json: the public key of the energy meter of DE*GEF*E1*1 is no uncompressed P-256 key identified by its SHA-256`);
    if (!spkiOf(rsa).equals(rsa) || !rsa.subarray(-5).equals(Buffer.from([ 0x02, 0x03, 0x01, 0x00, 0x01 ])))
        fail(`${KEYS_TS}: the RSA key is no key of the exponent 65537`);
    if (!certificate.publicKey.export({ format: 'der', type: 'spki' }).equals(meter) || !certificate.checkIssued(authority) || !certificate.verify(authority.publicKey) || !authority.verify(authority.publicKey))
        fail(`${KEYS_TS}: the certificate of the meter key is not of it, or not issued by the authority`);

    const meterKeyOf = (id, description, reason, key, more = {}) =>
        version(id, KEYS, `The public key of the energy meter of DE*GEF*E1*1 ${description}.`, reason,
                [ { op: 'replace', path: meterKey, value: { '@id': sha256(key), key: b64(key), ...more } } ]);
    const changed    = (key, change) => { const copy = Buffer.from(key); change(copy); return copy; };

    version('version-meter-key-without-key',      KEYS, 'The public key of the energy meter of DE*GEF*E1*1 without its key.',
            'A measurement public key needs its identification and its key!',                  [ { op: 'remove', path: `${meterKey}/key` } ]);
    version('version-meter-key-id-not-its-digest', KEYS, 'The public key of the energy meter of DE*GEF*E1*1 identified by its SHA-256 in upper case.',
            `The identification '${sha256(qaKey).toUpperCase()}' of a measurement public key is not the SHA-256 '${sha256(qaKey)}' of its key!`,
            [ { op: 'replace', path: `${meterKey}/@id`, value: sha256(qaKey).toUpperCase() } ]);
    meterKeyOf('version-meter-key-point-not-on-curve', 'its last octet changed, identified anew: a point not on the curve P-256',
               `${SPKI}Invalid point coordinates`,                                            changed(qaKey, key => { key[90] ^= 1; }));
    meterKeyOf('version-meter-key-point-encoding', 'its point of the encoding 5, identified anew: neither compressed, uncompressed nor hybrid',
               `${SPKI}Invalid point encoding 5`,                                             changed(qaKey, key => { key[26] = 5; }));
    meterKeyOf('version-meter-key-not-der',        'of the length of its outer SEQUENCE in the long form, 0x81 0x59, identified anew: BER, not DER',
               'A measurement public key must be DER encoded!',                              Buffer.concat([ Buffer.from([ 0x30, 0x81 ]), qaKey.subarray(1) ]));
    meterKeyOf('version-meter-key-rsa-exponent-even', 'an RSA key of the exponent 65536, identified by its SHA-256',
               `${SPKI}RSA publicExponent is even`,                                          changed(rsa, key => { key[key.length - 1] = 0; }));
    meterKeyOf('version-meter-key-ed25519-small-order', 'an Ed25519 key of the point (0, 1), of the order 1, identified by its SHA-256',
               `${SPKI}invalid public key`,                                                  Buffer.concat([ Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from([ 1 ]), Buffer.alloc(31) ]));
    meterKeyOf('version-meter-key-certificate-not-of-the-key', 'with the certificate chain of another key',
               'The first certificate of a measurement public key must be the one of the key!', qaKey, { certificateChain: chain.map(b64) });
    meterKeyOf('version-meter-key-certificate-not-issued', 'the key of a certificate, with its certificate twice: the first not issued by the second',
               'The certificate 1 of a measurement public key is not issued by the certificate 2!', meter, { certificateChain: [ b64(chain[0]), b64(chain[0]) ] });
    meterKeyOf('version-meter-key-certificate-not-der', 'the key of a certificate, with its certificate followed by a zero octet, and its issuer',
               'The certificate 1 of a measurement public key must be DER encoded!', meter, { certificateChain: [ b64(Buffer.concat([ chain[0], Buffer.from([ 0 ]) ])), b64(chain[1]) ] });

}

/** A JSON pointer as the dotted path WWCP_POI names it in its words, `chargingStationOperators[0].chargingPools[1]`. */
const dottedOf = (pointer) => pointer.split('/').slice(1).reduce((path, token) => /^\d+$/.test(token) ? `${path}[${token}]` : path === '' ? token : `${path}.${token}`, '');

function refusalVectors() {

    const vectors = [];
    const refuse  = (vector) => vectors.push({ expected: 'refused', ...vector });

    // Every patch must name what it changes, and change it.
    const patched = (file, pointer, patch) => {
        const document = at(jsonRun(file), pointer);
        for (const operation of patch) {
            if (operation.op === 'add') continue;
            const before = at(document, operation.path);
            if (operation.op === 'replace' && JSON.stringify(before) === JSON.stringify(operation.value))
                fail(`${file}${pointer}${operation.path}: the patch changes nothing`);
        }
        return { file, pointer, patch };
    };

    const genesis  = jsonRun('published/QA-genesis.json');
    const commit0  = genesis.commit;
    const hexToB64 = (hex) => Buffer.from(hex, 'hex').toString('base64');

    // ---- Commits (5.1, 3.1): their @id is the digest of their content.
    refuse({ id: 'commit-revision',           kind: 'commit', basis: `${SPEC}, 5.1`, description: 'The revision of the genesis commit changed: its @id is no longer the digest of its content.',            document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/revision', value: 1 } ]) });
    refuse({ id: 'commit-id',                 kind: 'commit', basis: `${SPEC}, 5.1`, description: 'Another @id.',                                                                                           document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/@id', value: '0'.repeat(64) } ]) });
    refuse({ id: 'commit-id-uppercase',       kind: 'commit', basis: `${SPEC}, 5.1`, description: 'The @id in uppercase hexadecimal digits: identifications are lowercase.',                                 document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/@id', value: commit0['@id'].toUpperCase() } ]) });
    refuse({ id: 'commit-etag-base64',        kind: 'commit', basis: `${SPEC}, 3.1`, description: 'An ETag of a commit in base64: commits write ETags in hex, a reader refuses others.',                    document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/eTags/0', value: [ 'json', 'sha256', 'base64', hexToB64(commit0.eTags[0][3]) ] } ]) });
    refuse({ id: 'commit-etag-uppercase',     kind: 'commit', basis: `${SPEC}, 3.1`, description: 'An ETag digest of a commit in uppercase hex.',                                                          document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/eTags/0/3', value: commit0.eTags[0][3].toUpperCase() } ]) });
    refuse({ id: 'commit-without-tree',       kind: 'commit', basis: `${SPEC}, 5.1, 8.3`, description: 'A commit without its effectiveTree ETag.',                                                      document: patched('published/QA-genesis.json', '/commit', [ { op: 'remove', path: '/eTags/2' } ]) });
    refuse({ id: 'commit-context',            kind: 'commit', basis: `${SPEC}, 1.1`, description: 'Another JSON-LD context.',                                                                               document: patched('published/QA-genesis.json', '/commit', [ { op: 'add', path: '/@context', value: 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v2' } ]) });
    refuse({ id: 'commit-etag-algorithm',     kind: 'commit', basis: `${SPEC}, 3.1`, description: 'An ETag of an algorithm POI does not know.',                                                            document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/eTags/0/1', value: 'sha1' } ]) });
    refuse({ id: 'commit-network',            kind: 'commit', basis: `${SPEC}, 5.1`, description: 'Another roaming network.',                                                                               document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/roamingNetworkId', value: 'QB' } ]) });

    // ---- Signatures of commits and checkpoints (5.4): read in one form only, its own properties, the signer a text, none
    //      of them empty, and embedded in a commit or checkpoint without a JSON-LD context (WWCP_POI b43ff1a, refused in the
    //      words of WWCP_POI.TS since 7c6f91c). They are no part of what identifies a commit or checkpoint, so that only the
    //      signature is refused.
    quoted(SPEC, 'A reader MUST refuse a signature naming another property, whatever else it names being signed by nobody, a `signer`', 'the one form of a commit or checkpoint signature of 5.4');
    const SIGNATURE_BASIS = `${SPEC}, 5.4`;
    const signed0 = commit0.signatures?.[0] ?? fail('published/QA-genesis.json: its commit is not signed');
    if (typeof signed0.signer !== 'string' || !/\.\d{3}Z$/.test(signed0.signedAt))
        fail('published/QA-genesis.json: the first signature of its commit names no signer, or not its signedAt with milliseconds');

    refuse({ id: 'commit-signature-other-property',  kind: 'commit', basis: SIGNATURE_BASIS, reason: "A signature of a commit must not name the property 'comment'!",
             description: 'A signature of the genesis commit naming a property of its own besides those of a signature: whatever else it names is signed by nobody.',
             document: patched('published/QA-genesis.json', '/commit', [ { op: 'add', path: '/signatures/0/comment', value: 'signed by nobody' } ]) });
    refuse({ id: 'commit-signature-context',         kind: 'commit', basis: SIGNATURE_BASIS, reason: "A signature of a commit must not name the property '@context'!",
             description: 'A signature of the genesis commit naming the JSON-LD context of commit signatures: embedded in a commit, a signature names none, though on its own it may.',
             document: patched('published/QA-genesis.json', '/commit', [ { op: 'add', path: '/signatures/0/@context', value: CONTEXTS.commitSignature } ]) });
    refuse({ id: 'commit-signature-signer-number',   kind: 'commit', basis: SIGNATURE_BASIS, reason: 'The signer of a signature of a commit must be a text!',
             description: 'A signature of the genesis commit naming its signer as a number.',
             document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/signatures/0/signer', value: 1 } ]) });
    refuse({ id: 'commit-signature-role-blank',      kind: 'commit', basis: SIGNATURE_BASIS, reason: 'The role of a signature of a commit must not be empty!',
             description: 'A signature of the genesis commit in the role " ": a role of nothing is refused when read, before anything counts it.',
             document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/signatures/0/role', value: ' ' } ]) });
    refuse({ id: 'commit-signature-signedAt-seconds', kind: 'commit', basis: SIGNATURE_BASIS, reason: 'The signedAt of a signature of a commit',
             description: 'A signature of the genesis commit with its signedAt without milliseconds: it is signed as text, written as yyyy-MM-ddTHH:mm:ss.fffZ.',
             document: patched('published/QA-genesis.json', '/commit', [ { op: 'replace', path: '/signatures/0/signedAt', value: signed0.signedAt.replace(/\.\d{3}Z$/, 'Z') } ]) });

    // ---- Change sets (4, 5.2): identified by their content, naming only what they were rebased from, with changes
    //      (csharp-review 4). The commit of each is identified anew, so that only its change set is refused.
    const contentId   = (changeSet) => sha256(utf8(canonical({ ...without(changeSet, '@id', 'signatures'), '@context': 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/changeSet/v3' })));
    const commitIdOf  = (commit)    => (commit['@id'].length === 128 ? sha512 : sha256)(utf8(canonical({ ...without(commit, '@id', 'signatures', 'changeSet'),
                                                                                                         '@context':  'https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v3',
                                                                                                         changeSet:   without(commit.changeSet, 'signatures', '@context') })));

    const commitN     = parseRaw(readRun('published/QA-commit.json'));
    const otherN      = parseRaw(readRun('published/QA-commits-since-genesis.json'))[0].changeSet;

    if (contentId(commitN.changeSet) !== commitN.changeSet['@id'] || contentId(otherN) !== otherN['@id'] || commitIdOf(commitN) !== commitN['@id'])
        fail('the change sets and the commit of the run are not identified as this script identifies them');

    // The change set of the commit changed as given, identified anew by its content unless it names its @id, and its commit
    // identified anew.
    const changeSetPatch = (changes, changeSetId, commit = commitN) => {
        const changeSet = { ...commit.changeSet, ...changes };
        const id        = changeSetId ?? contentId(changeSet);
        return [ ...Object.entries(changes).map(([ property, value ]) => ({ op: property in commit.changeSet ? 'replace' : 'add', path: `/changeSet/${property}`, value })),
                 { op: 'replace', path: '/changeSet/@id', value: id },
                 { op: 'replace', path: '/@id',           value: commitIdOf({ ...commit, changeSet: { ...changeSet, '@id': id } }) } ];
    };

    refuse({ id: 'changeSet-id',              kind: 'commit', basis: `${SPEC}, 4, 5.2`, description: 'The change set of a commit has the @id of another change set of the run, its commit identified anew: a change set is identified by its content, nobody names another one with its @id (csharp-review 4).', document: patched('published/QA-commit.json', '', changeSetPatch({}, otherN['@id'])) });
    refuse({ id: 'changeSet-rebasedFrom',     kind: 'commit', basis: `${SPEC}, 4, 5.2`, description: 'The change set of a commit names another change set of the run, with its ETags, as the one it was rebased from, identified anew by its content: it was not rebased from it (csharp-review 4).', document: patched('published/QA-commit.json', '', changeSetPatch({ metadata: { rebasedFrom: [ { '@id': otherN['@id'], beforeETags: otherN.beforeETags, afterETags: otherN.afterETags } ] } })) });
    refuse({ id: 'changeSet-without-changes', kind: 'commit', basis: `${SPEC}, 4, 5.2`, description: 'The change set of a commit with one parent without changes, identified anew by its content: it would change nothing.', document: patched('published/QA-commit.json', '', changeSetPatch({ changes: [] })) });
    refuse({ id: 'changeSet-merge-id',        kind: 'commit', basis: `${SPEC}, 4, 5.2, 5.3`, description: 'The change set of a commit with one parent named as the change set of a merge, which only a merge commit has.', document: patched('published/QA-commit.json', '', changeSetPatch({}, 'merge-' + '0'.repeat(32))) });

    // Rebased with a change naming no old value: only old values tell that a change set committed meanwhile changed what it
    // changes, which the rebase would have overwritten (csharp-review 12). It names the change set it was rebased from
    // rightly, with the ETags of another change set of the run, so that only the missing old value is refused. The commit is
    // the last one of epoch 2 that changes what is there: the head commit only adds since example A14.
    const commitsToHead    = parseRaw(readRun('proofs/QA-epoch-2-commits-to-head.json'));
    const changing         = commitsToHead.findLastIndex(commit => commit.changeSet.changes.some(change => 'oldValue' in change && change.kind !== 'Add' && change.kind !== 'AddElement'));
    const commitU          = commitsToHead[changing] ?? fail('proofs/QA-epoch-2-commits-to-head.json: no change of a change set names an old value');

    if (contentId(commitU.changeSet) !== commitU.changeSet['@id'] || commitIdOf(commitU) !== commitU['@id'])
        fail('the commit of the run that changes what is there is not identified as this script identifies it');

    const withoutOldValues = commitU.changeSet.changes.map(change => without(change, 'oldValue'));
    const rebasedOriginal  = { ...commitU.changeSet, changes: withoutOldValues, beforeETags: otherN.beforeETags, afterETags: otherN.afterETags };

    refuse({ id: 'changeSet-rebased-without-old-value', kind: 'commit', basis: `${SPEC}, 4; csharp-review 12`, reason: 'which was rebased, has no old value',
             description: 'The change set of a commit without the old value of its change, naming the change set it was rebased from rightly, identified anew: a rebase without old values may have overwritten a concurrent change.',
             document: patched('proofs/QA-epoch-2-commits-to-head.json', `/${changing}`, changeSetPatch({ changes: withoutOldValues, metadata: { rebasedFrom: [ { '@id': contentId(rebasedOriginal), beforeETags: otherN.beforeETags, afterETags: otherN.afterETags } ] } }, undefined, commitU)) });

    // ---- Checkpoints (10.1): their @id is the digest of their content.
    refuse({ id: 'checkpoint-sequence',       kind: 'checkpoint', basis: `${SPEC}, 10.1`, description: 'Another sequence.',                                                                            document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/sequence', value: 2 } ]) });
    refuse({ id: 'checkpoint-previous',       kind: 'checkpoint', basis: `${SPEC}, 10.1`, description: 'Another previous checkpoint.',                                                                 document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/previousId', value: '0'.repeat(64) } ]) });
    refuse({ id: 'checkpoint-commits-root',   kind: 'checkpoint', basis: `${SPEC}, 10.1`, description: 'Another root of its commits.',                                                                 document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/commits/@merkleRoot', value: '0'.repeat(64) } ]) });
    refuse({ id: 'checkpoint-epoch',          kind: 'checkpoint', basis: `${SPEC}, 10.1, 11`, description: 'A checkpoint of epoch 1 without "epoch": its @id is calculated with it (csharp-review 11).', document: patched('published/QA-checkpoint-1.json', '', [ { op: 'remove', path: '/epoch' } ]) });

    // ---- Signatures of checkpoints (5.4, 10.2), as those of commits.
    if (typeof jsonRun('published/QA-checkpoint-1.json').signatures?.[0]?.signer !== 'string')
        fail('published/QA-checkpoint-1.json: its first signature names no signer');

    refuse({ id: 'checkpoint-signature-other-property', kind: 'checkpoint', basis: `${SPEC}, 5.4, 10.2`, reason: "A signature of a checkpoint must not name the property 'comment'!",
             description: 'A signature of the checkpoint naming a property of its own besides those of a signature: whatever else it names is signed by nobody.',
             document: patched('published/QA-checkpoint-1.json', '', [ { op: 'add', path: '/signatures/0/comment', value: 'signed by nobody' } ]) });
    refuse({ id: 'checkpoint-signature-context',        kind: 'checkpoint', basis: `${SPEC}, 5.4, 10.2`, reason: "A signature of a checkpoint must not name the property '@context'!",
             description: 'A signature of the checkpoint naming the JSON-LD context of checkpoint signatures: embedded in a checkpoint, a signature names none.',
             document: patched('published/QA-checkpoint-1.json', '', [ { op: 'add', path: '/signatures/0/@context', value: CONTEXTS.checkpointSignature } ]) });
    refuse({ id: 'checkpoint-signature-signer-number',  kind: 'checkpoint', basis: `${SPEC}, 5.4, 10.2`, reason: 'The signer of a signature of a checkpoint must be a text!',
             description: 'A signature of the checkpoint naming its signer as a number.',
             document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/signatures/0/signer', value: 1 } ]) });

    // ---- Versions (3.1): the eTags a roaming network lists are the ETags of its content.
    refuse({ id: 'version-name',              kind: 'version', basis: `${SPEC}, 3.1`, description: 'The name of the network changed, its eTags not: they no longer are those of its content.',   document: patched('published/QA-genesis.json', '/roamingNetwork', [ { op: 'replace', path: '/name/en', value: 'Quality Assurance!' } ]) });
    refuse({ id: 'version-etag',              kind: 'version', basis: `${SPEC}, 3.1`, description: 'One ETag it lists is another.',                                                                 document: patched('published/QA-genesis.json', '/roamingNetwork', [ { op: 'replace', path: '/eTags/1', value: [ 'cbor', 'sha256', 'hex', '0'.repeat(64) ] } ]) });
    refuse({ id: 'version-context',           kind: 'version', basis: `${SPEC}, 3.1`, description: 'Another JSON-LD context.',                                                                       document: patched('published/QA-genesis.json', '/roamingNetwork', [ { op: 'replace', path: '/@context', value: 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/v2' } ]) });

    // ---- Versions: identifications unique within the roaming network, not only within their party, compared without
    //      case (RoamingNetwork.cs, DuplicateGridConnectionPoint to DuplicateEnergyMeterTemplate). The head of the run with
    //      one of them named twice by a party added without keys, without its eTags, so that only the identification is
    //      refused; the refusal names it (`reason`), as both implementations word it.
    const qa        = jsonRun('published/QA.json');
    const created   = qa.created;
    const gef       = qa.chargingStationOperators.find(operator => operator['@id'] === 'DE*GEF') ?? fail('QA.json: no charging station operator DE*GEF');
    const release   = qa.transparencySoftwareManufacturers?.[0]?.transparencySoftware?.[0]  ?? fail('QA.json: no transparency software release');
    const ptb       = qa.conformityAssessmentBodies?.find(body => body['@id'] === 'PTB')    ?? fail('QA.json: no conformity assessment body PTB');
    const has       = (entities, id) => (entities ?? []).some(entity => entity['@id'] === id) || fail(`QA.json: no ${id}`);
    const twice     = (id, basis, description, reason, patch) =>
                          refuse({ id, kind: 'version', basis, description, reason, document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, ...patch ]) });

    has(gef.EVSEGroups,           'DE*GEF*EG_AC');
    has(gef.energyMeterTemplates, 'DE*GEF*EMT_AC');
    has(gef.chargingPools.flatMap(pool => pool.chargingStations).flatMap(station => station.EVSEs).map(evse => evse.energyMeter).filter(Boolean), 'DE*GEF*M1*1');
    has([ release ],                         'GraphDefined:chargy-1.5.0');
    const TSM_GD    = `/transparencySoftwareManufacturers/${qa.transparencySoftwareManufacturers.findIndex(manufacturer => manufacturer['@id'] === 'GraphDefined')}`;
    const CAB_PTB   = `/conformityAssessmentBodies/${qa.conformityAssessmentBodies.findIndex(body => body['@id'] === 'PTB')}`;
    const ptb0042of = (id) => ({ ...ptb.certificates.find(certificate => certificate['@id'] === 'PTB:2026-0042'), '@id': id });
    if (at(qa, `${TSM_GD}/transparencySoftware/0/@id`) !== 'GraphDefined:chargy-1.5.0' || at(qa, `${CAB_PTB}/@id`) !== 'PTB')
        fail('QA.json: the release of GraphDefined or the PTB is not where the vectors patch them');
    has(ptb.certificates,                     'PTB:2026-0042');

    twice('version-twice-group',                 `${SPEC}, 9.3`,
          'The e-mobility provider DE-GEF, of the prefix of the charging station operator DE*GEF, has an EVSE group of the identification of one of the operator, its suffix in lowercase.',
          "The EVSE group 'DE*GEF*EG_ac' must not be given twice in the roaming network",
          [ { op: 'add', path: '/eMobilityProviders', value: [ { '@id': 'DE-GEF', EVSEGroups: [ { '@id': 'DE*GEF*EG_ac', created, lastChange: created } ], created, lastChange: created } ] } ]);

    twice('version-twice-energy-meter',          'libs/WWCP_POI/docs/EnergyMeter.md',
          'A grid connection point of the grid operator DE*NET has an energy meter of the identification of the one of an EVSE of DE*GEF, in lowercase.',
          "The energy meter 'de*gef*m1*1' must not be given twice in the roaming network",
          [ { op: 'add', path: '/gridOperators', value: [ { '@id': 'DE*NET', gridConnectionPoints: [ { '@id': 'connection-1', energyMeter: { '@id': 'de*gef*m1*1', created, lastChange: created } } ], created, lastChange: created } ] } ]);

    twice('version-twice-grid-connection-point', `${SPEC}, 4.1`,
          'Two grid operators have a grid connection point of the same identification, in another case.',
          "The grid connection point 'CONNECTION-1' of the grid operator 'DE*NET' must be unique within the roaming network, but the grid operator 'DE*NE2' has it too",
          [ { op: 'add', path: '/gridOperators', value: [ { '@id': 'DE*NE2', gridConnectionPoints: [ { '@id': 'connection-1' } ], created, lastChange: created },
                                                          { '@id': 'DE*NET', gridConnectionPoints: [ { '@id': 'CONNECTION-1' } ], created, lastChange: created } ] } ]);

    twice('version-twice-energy-meter-template', `${SPEC}, 9.1`,
          'The grid operator DE*NET has an energy meter template of the identification of one of DE*GEF, in lowercase.',
          "The energy meter template 'de*gef*emt_ac' must not be given twice in the roaming network",
          [ { op: 'add', path: '/gridOperators', value: [ { '@id': 'DE*NET', energyMeterTemplates: [ { '@id': 'de*gef*emt_ac', created, lastChange: created } ], created, lastChange: created } ] } ]);

    // An operator indexes its charging stations, EVSEs and energy meters by their identifications and refuses one given
    // twice (WWCP_POI e76e5d0, WWCP_POI.TS 0b6baea): before, WWCP_POI3 took a station in two pools of an operator, or an
    // EVSE in two of its stations, and kept the first - and proofs, price statements and evidence name them by their
    // identifications alone. Each copy is inserted in the ordinal order of its array (2), what it embeds left out, so
    // only the one identification is given twice.
    const GEF_AT    = `/chargingStationOperators/${qa.chargingStationOperators.indexOf(gef)}`;
    const stationS1 = gef.chargingPools[0].chargingStations[0];
    const evseE11   = stationS1.EVSEs[0];
    if (gef.chargingPools[1]?.chargingStations?.[0]?.['@id'] !== 'DE*GEF*S3' || stationS1['@id'] !== 'DE*GEF*S1' || evseE11['@id'] !== 'DE*GEF*E1*1' ||
        gef.chargingPools[0].chargingStations[1]?.EVSEs?.[0]?.energyMeter?.['@id'] !== 'DE*GEF*M2*1' || evseE11.energyMeter?.['@id'] !== 'DE*GEF*M1*1')
        fail('QA.json: the stations, EVSEs and energy meters of DE*GEF are not where the vectors patch them');
    const stripped  = (entity, ...properties) => Object.fromEntries(Object.entries(entity).filter(([ key ]) => !properties.includes(key)));

    twice('version-twice-station-of-operator',   `${SPEC}, 2`,
          'DE*GEF has its charging station DE*GEF*S1 in DE*GEF*P1 and again in DE*GEF*P2, the second time without its EVSEs.',
          "The charging station 'DE*GEF*S1' of the operator 'DE*GEF' must not be given twice!",
          [ { op: 'add', path: `${GEF_AT}/chargingPools/1/chargingStations/0`, value: stripped(stationS1, 'EVSEs') } ]);

    twice('version-twice-evse-of-operator',      `${SPEC}, 2`,
          'DE*GEF has its EVSE DE*GEF*E1*1 in DE*GEF*S1 and again in DE*GEF*S2, the second time without its energy meter.',
          "The EVSE 'DE*GEF*E1*1' of the operator 'DE*GEF' must not be given twice!",
          [ { op: 'add', path: `${GEF_AT}/chargingPools/0/chargingStations/1/EVSEs/0`, value: stripped(evseE11, 'energyMeter') } ]);

    twice('version-twice-energy-meter-of-operator', `${SPEC}, 2`,
          'The EVSE DE*GEF*E2*1 of DE*GEF has the energy meter DE*GEF*M1*1, which its EVSE DE*GEF*E1*1 has.',
          "The energy meter 'DE*GEF*M1*1' of the operator 'DE*GEF' must not be given twice!",
          [ { op: 'replace', path: `${GEF_AT}/chargingPools/0/chargingStations/1/EVSEs/0/energyMeter/@id`, value: 'DE*GEF*M1*1' } ]);

    // Since a release is identified under its manufacturer and a certificate under its body (S36), only the same owner can
    // name one twice: GraphDefined its release, the PTB its certificate, the second time in another case - which its own
    // releases or certificates refuse, so that no two owners are ever compared (DuplicateTransparencySoftware and
    // DuplicateConformityCertificate of WWCP_POI3 no longer refuse a version first).
    twice('version-twice-release',               'libs/WWCP_POI/docs/TransparencySoftwareManufacturer.md',
          'GraphDefined has its release a second time, its identification in uppercase: refused by the releases of the manufacturer, before those of the roaming network.',
          "The transparency software release 'GRAPHDEFINED:CHARGY-1.5.0' of the transparency software manufacturer 'GraphDefined' must not be given twice!",
          [ { op: 'add', path: `${TSM_GD}/transparencySoftware/-`, value: { ...release, '@id': 'GRAPHDEFINED:CHARGY-1.5.0' } } ]);

    twice('version-twice-certificate',           'libs/WWCP_POI/docs/ConformityAssessmentBody.md',
          'The PTB has its certificate PTB:2026-0042 a second time, its identification in lowercase: refused by the certificates of the body, before those of the roaming network.',
          "The certificate 'ptb:2026-0042' of the conformity assessment body 'PTB' must not be given twice!",
          [ { op: 'add', path: `${CAB_PTB}/certificates/-`, value: ptb0042of('ptb:2026-0042') } ]);

    // ---- Versions: a release identified under its manufacturer, a certificate under the body issuing it - its owner's
    //      identification, a colon and a name of its own without one, the prefix compared without case (S36). A version
    //      holding one identified otherwise is refused, before any duplicate: what another owner gives the identification
    //      of one too.
    const S36       = `${SPEC}, 4.1, How releases and certificates are identified`;
    const notUnder  = (kind, id, owner) => kind === 'release'
                          ? `The transparency software release '${id}' of the manufacturer '${owner}' is not identified as one of it: by '${owner}:' and a name without a colon!`
                          : `The certificate '${id}' of the conformity assessment body '${owner}' is not identified as one of it: by '${owner}:' and a name without a colon!`;
    const ofOCC     = (releases) => [ { op: 'add', path: '/transparencySoftwareManufacturers/-', value: { '@id': 'OpenChargingCloud', name: { en: 'Open Charging Cloud' }, transparencySoftware: releases, created, lastChange: created } } ];
    const ofVDE     = (certificates) => [ { op: 'add', path: '/conformityAssessmentBodies/-', value: { '@id': 'VDE', name: { de: 'VDE Prüf- und Zertifizierungsinstitut' }, notifiedFor: [ 'MID' ], certificates, created, lastChange: created } } ];

    twice('version-release-not-under-its-manufacturer', S36,
          'OpenChargingCloud has a release identified without its manufacturer: CHARGY-1.5.0, the identification of the release of GraphDefined before S36, in uppercase.',
          notUnder('release', 'CHARGY-1.5.0', 'OpenChargingCloud'), ofOCC([ { ...release, '@id': 'CHARGY-1.5.0' } ]));
    twice('version-release-under-another-manufacturer', S36,
          'OpenChargingCloud has a release of the identification of the one of GraphDefined, in uppercase: under another manufacturer.',
          notUnder('release', 'GRAPHDEFINED:CHARGY-1.5.0', 'OpenChargingCloud'), ofOCC([ { ...release, '@id': 'GRAPHDEFINED:CHARGY-1.5.0' } ]));
    twice('version-release-name-with-a-colon',   S36,
          'GraphDefined has a second release whose name has a colon: GraphDefined:chargy:2.0.',
          notUnder('release', 'GraphDefined:chargy:2.0', 'GraphDefined'),
          [ { op: 'add', path: `${TSM_GD}/transparencySoftware/-`, value: { ...release, '@id': 'GraphDefined:chargy:2.0', version: '2.0' } } ]);
    twice('version-release-without-a-name',      S36,
          'GraphDefined has a second release of its identification and a colon alone: GraphDefined:.',
          notUnder('release', 'GraphDefined:', 'GraphDefined'),
          [ { op: 'add', path: `${TSM_GD}/transparencySoftware/-`, value: { ...release, '@id': 'GraphDefined:', version: '2.0' } } ]);
    twice('version-certificate-not-under-its-body', S36,
          'The VDE has a certificate identified without its body: ptb-2026-0042, the identification of the certificate of the PTB before S36, in lowercase.',
          notUnder('certificate', 'ptb-2026-0042', 'VDE'), ofVDE([ ptb0042of('ptb-2026-0042') ]));
    twice('version-certificate-under-another-body', S36,
          'The VDE has a certificate of the identification of the one of the PTB, in lowercase: under another body.',
          notUnder('certificate', 'ptb:2026-0042', 'VDE'), ofVDE([ ptb0042of('ptb:2026-0042') ]));

    // ---- Versions: hardware revisions, firmware versions and serial numbers taken as given, not trimmed, not empty and
    //      neither beginning nor ending with whitespace as Char.IsWhiteSpace tells it (HardwareRevision, FirmwareVersion
    //      and SerialNumber of WWCP_POI2), and those of a model or of a certificate each once (ModelVersions.Of). The head
    //      of the run with one of them changed, without its eTags, as above; the refusal names it (`reason`) in the words
    //      both share: WWCP_POI names the text it refuses, not what names it.
    const DOCS      = 'libs/WWCP_POI/docs';
    const named     = (pointer, id) => at(qa, `${pointer}/@id`) === id ? pointer : fail(`QA.json#${pointer} is not ${id}`);
    const station   = named('/chargingStationOperators/0/chargingPools/0/chargingStations/0', 'DE*GEF*S1');
    const meter     = named(`${station}/EVSEs/0/energyMeter`,                                'DE*GEF*M1*1');
    const acStation = named('/chargingStationOperators/0/chargingStationTemplates/0',        'DE*GEF*ST_AC');
    const dcMeter   = named('/chargingStationOperators/0/energyMeterTemplates/1',            'DE*GEF*EMT_DC');
    const dc300     = named('/chargingStationManufacturers/0/chargingStationModels/1',       'GD-DC300');
    const kdm500    = named('/energyMeterManufacturers/0/energyMeterModels/0',               'KDM-500');
    const ptb0017   = named('/conformityAssessmentBodies/2/certificates/0',                  'PTB:2026-0017');
    const ptb0042   = named('/conformityAssessmentBodies/2/certificates/1',                  'PTB:2026-0042');
    const withText  = twice;

    quoted(`${DOCS}/ChargingStation.md`,             'taken as given, not trimmed and compared ordinally, case included; not empty and neither beginning nor ending with whitespace.', 'that a serial number is taken as given');
    quoted(`${DOCS}/EnergyMeter.md`,                 'taken as given, not trimmed and compared ordinally, case included; not empty and neither beginning nor ending with whitespace.', 'that a serial number is taken as given');
    quoted(`${DOCS}/ChargingStationManufacturer.md`, 'The hardware revisions it was built in, each once, none empty or beginning or ending with whitespace, in their given order.',      'that a model names its hardware revisions each once, as given');
    quoted(`${DOCS}/EnergyMeterManufacturer.md`,     'The hardware revisions it was built in, each once, none empty or beginning or ending with whitespace, in their given order.',      'that a model names its hardware revisions each once, as given');
    quoted(`${DOCS}/ConformityAssessmentBody.md`,    'each one of the `hardwareRevisions` of the model, compared ordinally; each once, in their given order.',                          'that a certificate names the hardware revisions of its model each once');

    withText('version-text-station-serial-number',          `${DOCS}/ChargingStation.md`,
             'The charging station DE*GEF*S1 names a serial number ending with a tab: a serial number is taken as given, not trimmed, and neither begins nor ends with whitespace.',
             "Invalid serial number 'DCS-2026-001\t'!",
             [ { op: 'add', path: `${station}/serialNumber`, value: 'DCS-2026-001\t' } ]);

    withText('version-text-meter-serial-number',            `${DOCS}/EnergyMeter.md`,
             'The energy meter DE*GEF*M1*1 names its serial number with a space before it.',
             "Invalid serial number ' DCM-2026-001-1'!",
             [ { op: 'replace', path: `${meter}/serialNumber`, value: ' DCM-2026-001-1' } ]);

    withText('version-text-template-hardware-revision',     `${DOCS}/ChargingStationTemplate.md, ${DOCS}/ChargingStationManufacturer.md`,
             'The charging station template DE*GEF*ST_AC names an empty hardware revision: it gives one of the hardware revisions of its model, none of which is empty.',
             "Invalid hardware revision ''!",
             [ { op: 'replace', path: `${acStation}/hardwareRevision`, value: '' } ]);

    withText('version-text-template-firmware-version',      `${DOCS}/EnergyMeterTemplate.md, ${DOCS}/EnergyMeterManufacturer.md`,
             'The energy meter template DE*GEF*EMT_DC names its firmware version followed by U+0085 (NEL): whitespace as Char.IsWhiteSpace tells it, though String.prototype.trim keeps it.',
             "Invalid firmware version '3.2\u0085'!",
             [ { op: 'replace', path: `${dcMeter}/firmwareVersion`, value: '3.2\u0085' } ]);

    withText('version-text-model-hardware-revision',        `${DOCS}/EnergyMeterManufacturer.md`,
             'The energy meter model KDM-500 names a further hardware revision ending with a space.',
             "Invalid hardware revision '2.2 '!",
             [ { op: 'add', path: `${kdm500}/hardwareRevisions/-`, value: '2.2 ' } ]);

    withText('version-text-model-twice',                    `${DOCS}/ChargingStationManufacturer.md`,
             'The charging station model GD-DC300 names the firmware version 2.4.0 twice.',
             "A firmware version of the charging station model 'GD-DC300' must not be given twice!",
             [ { op: 'add', path: `${dc300}/firmwareVersions/-`, value: '2.4.0' } ]);

    withText('version-text-certificate-hardware-revision',  `${DOCS}/ConformityAssessmentBody.md, ${DOCS}/EnergyMeterManufacturer.md`,
             'The certificate PTB:2026-0017 names a further hardware revision with a space before it: it names hardware revisions of its model, none of which begins with whitespace.',
             "hardwareRevisions[1]: Invalid text representation of a hardware revision: ' 2.1'!",
             [ { op: 'add', path: `${ptb0017}/hardwareRevisions/-`, value: ' 2.1' } ]);

    withText('version-text-certificate-energy-meter',       `${DOCS}/ConformityAssessmentBody.md, ${DOCS}/EnergyMeterManufacturer.md`,
             'The energy meter the certificate PTB:2026-0042 was issued with names its firmware version followed by a no-break space (U+00A0).',
             "energyMeters[0]: firmwareVersions[0]: Invalid text representation of a firmware version: '3.2 '!",
             [ { op: 'replace', path: `${ptb0042}/energyMeters/0/firmwareVersions/0`, value: '3.2 ' } ]);

    withText('version-text-certificate-twice',              `${DOCS}/ConformityAssessmentBody.md`,
             'The certificate PTB:2026-0017 names the hardware revision 2.1 twice.',
             "A hardware revision of the certificate 'PTB:2026-0017' must not be given twice!",
             [ { op: 'add', path: `${ptb0017}/hardwareRevisions/-`, value: '2.1' } ]);

    withText('version-text-certificate-energy-meter-twice', `${DOCS}/ConformityAssessmentBody.md`,
             'The energy meter the certificate PTB:2026-0042 was issued with names the hardware revision 2.1 twice.',
             "A hardware revision of the certified energy meter model 'KDM-500' of 'KERNBERG' must not be given twice!",
             [ { op: 'add', path: `${ptb0042}/energyMeters/0/hardwareRevisions/-`, value: '2.1' } ]);

    // ---- Versions: a certificate as WWCP_POI takes it (ConformityCertificate and CertifiedEnergyMeter of WWCP_POI2): for
    //      exactly one model, with its manufacturer; at least one hardware revision and one firmware version, also of each
    //      energy meter it was issued with; an absolute documentURL, a legislation not empty, notBefore not after
    //      notAfter; at least one release, none twice, none both verified and compatible (compared without case, as
    //      releases are); energy meters of a charging station model only, each model once (without case, as models are).
    //      The head of the run with one certificate changed, without its eTags, as above; the refusal names it (`reason`)
    //      in the words of WWCP_POI. PTB:2026-0017 is for the energy meter model KDM-500, PTB:2026-0042 for the charging
    //      station model GD-DC300, issued with KDM-500.
    const CERTIFICATES = `${DOCS}/ConformityAssessmentBody.md`;
    const malformed    = (id, description, reason, patch) =>
                             refuse({ id, kind: 'version', basis: CERTIFICATES, description, reason,
                                      document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, ...patch ]) });

    quoted(CERTIFICATES, '- For exactly one model: `chargingStationManufacturerId` and `chargingStationModel`, or `energyMeterManufacturerId` and\n  `energyMeterModel`, each with its manufacturer.',
           'that a certificate is for exactly one model, with its manufacturer');
    quoted(CERTIFICATES, 'Mandatory, at least one: the hardware revisions of the model it covers',                                   'that a certificate names at least one hardware revision');
    quoted(CERTIFICATES, 'Mandatory, at least one: the firmware versions of the model it covers',                                     'that a certificate names at least one firmware version');
    quoted(CERTIFICATES, '| `documentURL` | URL | update/remove | Absolute;',                                                         'that the documentURL of a certificate is absolute');
    quoted(CERTIFICATES, '| `legislation` | string | update/remove | The legislation it is issued under, e.g. `MID`: one its body is `notifiedFor`. |',
           'what legislation a certificate names');
    quoted(CERTIFICATES, '| `notAfter` | timestamp | update/remove | End of validity; not before `notBefore`. |',                    'that a certificate ends no earlier than it begins');
    quoted(CERTIFICATES, '- At least one release in both lists together; a release not in both, not twice, not empty.',              'which releases a certificate names');
    quoted(CERTIFICATES, 'a model of an energy meter manufacturer of the network in at least one of its hardware revisions and firmware versions; each model once, in their given order; omitted when none. A certificate for an energy meter model names none.',
           'which energy meters a certificate names');

    malformed('version-certificate-model-none',
              'The certificate PTB:2026-0017 names no model: its energyMeterManufacturerId and energyMeterModel removed.',
              "The certificate 'PTB:2026-0017' must be for either a charging station model or an energy meter model!",
              [ { op: 'remove', path: `${ptb0017}/energyMeterManufacturerId` }, { op: 'remove', path: `${ptb0017}/energyMeterModel` } ]);

    malformed('version-certificate-model-both',
              'The certificate PTB:2026-0017 for the energy meter model KDM-500 of KERNBERG names the charging station model GD-DC300 of GraphDefined as well.',
              "The certificate 'PTB:2026-0017' must be for either a charging station model or an energy meter model!",
              [ { op: 'add', path: `${ptb0017}/chargingStationManufacturerId`, value: 'GraphDefined' }, { op: 'add', path: `${ptb0017}/chargingStationModel`, value: 'GD-DC300' } ]);

    malformed('version-certificate-model-without-manufacturer',
              'The certificate PTB:2026-0042 names the charging station model GD-DC300 without its manufacturer.',
              "The certificate 'PTB:2026-0042' must name the charging station model it is for with its manufacturer!",
              [ { op: 'remove', path: `${ptb0042}/chargingStationManufacturerId` } ]);

    malformed('version-certificate-manufacturer-without-model',
              'The certificate PTB:2026-0017 names the energy meter manufacturer KERNBERG without its model.',
              "The certificate 'PTB:2026-0017' must name the energy meter model it is for with its manufacturer!",
              [ { op: 'remove', path: `${ptb0017}/energyMeterModel` } ]);

    malformed('version-certificate-hardware-revisions-none',
              'The certificate PTB:2026-0017 names no hardware revision: an empty array.',
              "The certificate 'PTB:2026-0017' must name at least one hardware revision of its model!",
              [ { op: 'replace', path: `${ptb0017}/hardwareRevisions`, value: [] } ]);

    malformed('version-certificate-firmware-versions-none',
              'The certificate PTB:2026-0042 names no firmware version: none given.',
              "The certificate 'PTB:2026-0042' must name at least one firmware version of its model!",
              [ { op: 'remove', path: `${ptb0042}/firmwareVersions` } ]);

    // Without a slash before it: .NET on Linux takes "/certificates/…" as an absolute URI, of a file.
    malformed('version-certificate-document-url-relative',
              'The certificate PTB:2026-0017 names its documentURL as a relative reference, a path without scheme and host.',
              'documentURL: expected an absolute URL.',
              [ { op: 'replace', path: `${ptb0017}/documentURL`, value: 'certificates/PTB-2026-0017.pdf' } ]);

    malformed('version-certificate-legislation-empty',
              'The certificate PTB:2026-0042 names a legislation of a space alone.',
              'A legislation must not be empty.',
              [ { op: 'replace', path: `${ptb0042}/legislation`, value: ' ' } ]);

    malformed('version-certificate-validity-reversed',
              'The certificate PTB:2026-0017 ends a millisecond before it begins: its notAfter before its notBefore.',
              'notBefore must not exceed notAfter.',
              [ { op: 'replace', path: `${ptb0017}/notAfter`, value: new Date(Date.parse(at(qa, `${ptb0017}/notBefore`)) - 1).toISOString() } ]);

    malformed('version-certificate-release-none',
              'The certificate PTB:2026-0017 names no transparency software release, neither verified nor compatible.',
              'A document must identify at least one software release.',
              [ { op: 'replace', path: `${ptb0017}/verifiedTransparencySoftwareIds`, value: [] } ]);

    malformed('version-certificate-release-twice',
              'The certificate PTB:2026-0042 names its verified release GraphDefined:chargy-1.5.0 twice.',
              'Empty or duplicate TransparencySoftware reference.',
              [ { op: 'add', path: `${ptb0042}/verifiedTransparencySoftwareIds/-`, value: 'GraphDefined:chargy-1.5.0' } ]);

    malformed('version-certificate-release-both',
              'The certificate PTB:2026-0042 names its verified release GraphDefined:chargy-1.5.0 as compatible as well, in uppercase: releases are compared without case.',
              'A release cannot be both verified and merely compatible in the same document.',
              [ { op: 'add', path: `${ptb0042}/compatibleTransparencySoftwareIds/-`, value: 'GRAPHDEFINED:CHARGY-1.5.0' } ]);

    malformed('version-certificate-energy-meters-of-meter-model',
              'The certificate PTB:2026-0017 for the energy meter model KDM-500 names that model as an energy meter it was issued with: only a certificate of a charging station model names energy meters.',
              "The certificate 'PTB:2026-0017' of an energy meter model names no energy meters!",
              [ { op: 'add', path: `${ptb0017}/energyMeters`, value: [ { manufacturerId: 'KERNBERG', modelId: 'KDM-500', hardwareRevisions: [ '2.1' ], firmwareVersions: [ '3.2' ] } ] } ]);

    malformed('version-certificate-energy-meter-twice',
              'The certificate PTB:2026-0042 names the energy meter model KDM-500 of KERNBERG twice, the second time in lowercase: models are compared without case.',
              "The energy meter model 'KDM-500' of 'KERNBERG' must not be given twice in the certificate 'PTB:2026-0042'!",
              [ { op: 'add', path: `${ptb0042}/energyMeters/-`, value: { manufacturerId: 'KERNBERG', modelId: 'kdm-500', hardwareRevisions: [ '2.1' ], firmwareVersions: [ '3.2' ] } } ]);

    malformed('version-certificate-energy-meter-hardware-revisions-none',
              'The energy meter the certificate PTB:2026-0042 was issued with names no hardware revision: an empty array.',
              "The certified energy meter model 'KDM-500' of 'KERNBERG' must name at least one hardware revision!",
              [ { op: 'replace', path: `${ptb0042}/energyMeters/0/hardwareRevisions`, value: [] } ]);

    malformed('version-certificate-energy-meter-firmware-versions-none',
              'The energy meter the certificate PTB:2026-0042 was issued with names no firmware version: none given.',
              "The certified energy meter model 'KDM-500' of 'KERNBERG' must name at least one firmware version!",
              [ { op: 'remove', path: `${ptb0042}/energyMeters/0/firmwareVersions` } ]);

    // ---- Versions: a conformity assessment body as WWCP_POI takes it (ConformityAssessmentBody of WWCP_POI3): its
    //      notifiedBodyNumber four digits, the legislations it is notifiedFor none empty and each once, every certificate
    //      it issued under a legislation one it is notified for. The head of the run with PTB changed, which is notified
    //      for MID as 0102, without its eTags, as above (D14, fixed in WWCP_POI.TS 4ff1fc2).
    const ptbAt = named('/conformityAssessmentBodies/2', 'PTB');
    const bodyMalformed = (id, description, reason, patch) =>
                              refuse({ id, kind: 'version', basis: CERTIFICATES, description, reason,
                                       document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, ...patch ]) });
    if (JSON.stringify(at(qa, `${ptbAt}/notifiedFor`)) !== '["MID"]' || at(qa, `${ptbAt}/notifiedBodyNumber`) !== '0102' || at(qa, `${ptb0042}/legislation`) !== 'MID')
        fail('QA.json: PTB is no longer notified for MID alone as 0102, or PTB:2026-0042 not issued under MID');

    quoted(CERTIFICATES, 'Its number as a notified body: four digits, e.g. `0102`',                     'that a notified body number is four digits');
    quoted(CERTIFICATES, 'The legislations it is a notified body for, each once',                           'that a body is notified for each legislation once');
    quoted(CERTIFICATES, '`MID` and `CRA` (`ConformityAssessmentBody.Legislations`) are well known, any other nonempty text names another one.',
           'that a legislation is a nonempty text');

    bodyMalformed('version-body-certificate-not-notified',
              'The certificate PTB:2026-0042 is issued under the legislation CRA, for which its body, notified for MID, is no notified body.',
              "The certificate 'PTB:2026-0042' is issued under the legislation 'CRA', which the conformity assessment body 'PTB' is not notified for!",
              [ { op: 'replace', path: `${ptb0042}/legislation`, value: 'CRA' } ]);

    bodyMalformed('version-body-number-three-digits',
              'PTB names its notified body number in three digits, 102 for 0102.',
              "The notified body number '102' of the conformity assessment body 'PTB' must be four digits!",
              [ { op: 'replace', path: `${ptbAt}/notifiedBodyNumber`, value: '102' } ]);

    bodyMalformed('version-body-notified-for-empty',
              'PTB is notified for MID and for an empty legislation.',
              "A legislation the conformity assessment body 'PTB' is notified for must not be empty!",
              [ { op: 'replace', path: `${ptbAt}/notifiedFor`, value: [ '', 'MID' ] } ]);

    bodyMalformed('version-body-notified-for-twice',
              'PTB is notified for MID twice.',
              "A legislation the conformity assessment body 'PTB' is notified for must not be given twice!",
              [ { op: 'replace', path: `${ptbAt}/notifiedFor`, value: [ 'MID', 'MID' ] } ]);

    // Its legislations as the content holds them, in their ordinal order (SPECIFICATION.md 2, Written forms; WWCP_POI
    // 8108522, WWCP_POI.TS 9decdb5); its number and its legislations texts; its number one no other body has (S32).
    const bsiAt = named('/conformityAssessmentBodies/0', 'BSI');
    if ('notifiedBodyNumber' in at(qa, bsiAt))
        fail('QA.json: BSI names a notified body number already');
    quoted(SPEC,         'and the `notifiedFor`\n  of a conformity assessment body out of its ordinal order are refused', 'that a reader refuses a notifiedFor out of its ordinal order');
    quoted(SPEC,         '`measurands`, `notifiedFor`, `cardTypes`',                                    'that the content holds the legislations of a body in their ordinal order');
    quoted(CERTIFICATES, '- Two bodies can not have the same `notifiedBodyNumber`.',                     'that a notified body number names one body');

    bodyMalformed('version-body-notified-for-out-of-order',
              'PTB is notified for MID and CRA, in this order: not the ordinal one, in which the content holds them and WWCP_POI would write them again.',
              "The legislations the conformity assessment body 'PTB' is notified for are written in their ordinal order!",
              [ { op: 'replace', path: `${ptbAt}/notifiedFor`, value: [ 'MID', 'CRA' ] } ]);

    bodyMalformed('version-body-number-not-a-text',
              'PTB names its notified body number as the number 102.',
              'The notified body number must be a text!',
              [ { op: 'replace', path: `${ptbAt}/notifiedBodyNumber`, value: 102 } ]);

    bodyMalformed('version-body-notified-for-not-texts',
              'PTB names the legislation it is notified for as a text, not in an array.',
              'The legislations notified for must be a JSON array of texts!',
              [ { op: 'replace', path: `${ptbAt}/notifiedFor`, value: 'MID' } ]);

    bodyMalformed('version-body-number-twice',
              'BSI names the notified body number of PTB, 0102, as its own: the number of PTB, which follows BSI, is the one of BSI already.',
              "The notified body number '0102' of the conformity assessment body 'PTB' is the one of the conformity assessment body 'BSI' already!",
              [ { op: 'add', path: `${bsiAt}/notifiedBodyNumber`, value: '0102' } ]);

    // ---- Versions: EV Taler (concepts/EVTaler.md, phase 1): the merchant of a charging station operator at a GNU Taler
    //      merchant backend (EVTalerMerchant and EVTalerExchange of WWCP_POI3) - base URLs HTTPS, without user, query
    //      and fragment, ending in '/'; public keys as GNU Taler writes them; at least one exchange, each once, with an
    //      ISO 4217 currency but XXX and its name -, a charging pool naming the payment option EVTaler only with it, and
    //      signing keys of the usages POI knows, payments among them. The head of the run, which names no merchant, with
    //      the merchant of the example of ChargingStationOperator.md given, one of its values changed, or with a pool or
    //      a key changed, without its eTags, as above; the refusal names it (`reason`) in the words of WWCP_POI3.
    const OPERATOR    = EV_TALER_DOC;
    const POOL        = `${DOCS}/ChargingPool.md`;
    const gefAt       = named('/chargingStationOperators/0', 'DE*GEF');
    const pool1       = named(`${gefAt}/chargingPools/0`,  'DE*GEF*P1');
    const evTaler     = evTalerOfTheExample();
    const exchange    = evTaler.exchanges?.[0] ?? fail(`${OPERATOR}: the example of an EV Taler merchant names no exchange`);
    const CROCKFORD   = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    const lastBitsOf  = (key) => CROCKFORD.indexOf(key.at(-1)) & 0x0F;
    const merchant    = (changed) => [ { op: 'add', path: `${gefAt}/evTaler`, value: { ...evTaler, ...changed } } ];
    const withMerchant = twice;

    if (lastBitsOf(evTaler.merchantPublicKey) !== 0 || evTaler.merchantPublicKey.length !== 52)
        fail(`${OPERATOR}: the merchant public key of the example is no key as GNU Taler writes it`);
    if ('evTaler' in at(qa, gefAt) || 'paymentOptions' in at(qa, pool1))
        fail('QA.json: DE*GEF names an EV Taler merchant, or DE*GEF*P1 payment options, already');

    quoted(OPERATOR, 'The base URL of its instance at the merchant backend: HTTPS, without user, query and fragment, ending in `/`', 'what the merchant base URL is');
    quoted(OPERATOR, "52 characters of Crockford's Base32 in upper case, the last 4 bits zero",                                   'how a public key of GNU Taler is written');
    quoted(OPERATOR, '1..n exchanges it accepts, in the ordinal order of their `masterPublicKey`, each once.',                    'that a merchant accepts at least one exchange, each once');
    quoted(OPERATOR, '| `baseURL` | URL | Its base URL, as `merchantBaseURL`. |',                                                 'that the base URL of an exchange is one as the merchant base URL');
    quoted(OPERATOR, 'The ISO 4217 code of its coins, as the `currency` of a charging tariff; `XXX` is refused.',                 'which currency an exchange names');
    quoted(OPERATOR, 'Its name as drivers see it, mandatory',                                                                       'that an exchange names its name');
    quoted(OPERATOR, 'a charging pool or charging pool template of the operator naming `EVTaler` needs `evTaler`',                'that a pool naming EVTaler needs the merchant');
    quoted(POOL,     'a pool\nnaming it needs the `evTaler` merchant of its [operator]',                                            'that a pool naming EVTaler needs the merchant');
    quoted(OPERATOR, '`payments` (its `evTaler` merchant and its settlement statements of EV Taler sessions) and `party` (its other own properties, rotating its signing keys); everything without. In their ordinal order; unknown ones are refused.',
           'that the usages of a signing key are those POI knows');

    withMerchant('version-evtaler-pool-without-merchant', `${POOL}, ${OPERATOR}`,
                 'The charging pool DE*GEF*P1 names the payment option EVTaler, its operator DE*GEF no EV Taler merchant.',
                 "The charging pool 'DE*GEF*P1' names the payment option 'EVTaler', but its operator 'DE*GEF' has no EV Taler merchant!",
                 [ { op: 'add', path: `${pool1}/paymentOptions`, value: [ 'EVTaler' ] } ]);

    const merchantURL = (id, description, url, reason) =>
        withMerchant(id, OPERATOR, `DE*GEF names the EV Taler merchant of the example, its merchant base URL ${description}.`,
                     `The merchant base URL '${url}' must ${reason}`, merchant({ merchantBaseURL: url }));

    merchantURL('version-evtaler-merchant-url-http',     'with http instead of https', evTaler.merchantBaseURL.replace('https://', 'http://'),                    'be an HTTPS URL!');
    merchantURL('version-evtaler-merchant-url-user',     'naming a user',              evTaler.merchantBaseURL.replace('https://', 'https://gef@'),               'not name a user!');
    merchantURL('version-evtaler-merchant-url-query',    'with a query',               `${evTaler.merchantBaseURL}?instance=de-gef`,                               'have neither a query nor a fragment!');
    merchantURL('version-evtaler-merchant-url-no-slash', "not ending in '/'",          evTaler.merchantBaseURL.replace(/\/$/, ''),                                "end with '/'!");

    withMerchant('version-evtaler-merchant-key-lowercase', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, its merchant public key in lower case: the same key, but not as GNU Taler writes it.',
                 `An EV Taler merchant needs its merchant public key, as GNU Taler writes it, not '${evTaler.merchantPublicKey.toLowerCase()}'!`,
                 merchant({ merchantPublicKey: evTaler.merchantPublicKey.toLowerCase() }));

    const lastBitsSet = evTaler.merchantPublicKey.slice(0, -1) + CROCKFORD[CROCKFORD.indexOf(evTaler.merchantPublicKey.at(-1)) + 1];
    withMerchant('version-evtaler-merchant-key-last-bits', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, the last character of its merchant public key the next one of the alphabet: 52 characters of 5 bits are 260, a key of 32 bytes 256, the last 4 bits are zero.',
                 `An EV Taler merchant needs its merchant public key, as GNU Taler writes it, not '${lastBitsSet}'!`,
                 merchant({ merchantPublicKey: lastBitsSet }));

    withMerchant('version-evtaler-exchanges-none', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example without an exchange: an empty array.',
                 'A merchant accepts at least one exchange!',
                 merchant({ exchanges: [] }));

    withMerchant('version-evtaler-exchange-twice', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, its exchange twice.',
                 'An exchange must not be given twice!',
                 merchant({ exchanges: [ exchange, exchange ] }));

    withMerchant('version-evtaler-exchange-url-http', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, the base URL of its exchange with http instead of https.',
                 `The base URL of the exchange '${exchange.masterPublicKey}' '${exchange.baseURL.replace('https://', 'http://')}' must be an HTTPS URL!`,
                 merchant({ exchanges: [ { ...exchange, baseURL: exchange.baseURL.replace('https://', 'http://') } ] }));

    withMerchant('version-evtaler-exchange-key-lowercase', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, the master public key of its exchange in lower case.',
                 `An exchange needs its master public key, as GNU Taler writes it, not '${exchange.masterPublicKey.toLowerCase()}'!`,
                 merchant({ exchanges: [ { ...exchange, masterPublicKey: exchange.masterPublicKey.toLowerCase() } ] }));

    withMerchant('version-evtaler-exchange-currency-xxx', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, the currency of its exchange XXX: the ISO 4217 code of no currency.',
                 `The currency of the exchange '${exchange.masterPublicKey}' must be an ISO 4217 code, not 'XXX'!`,
                 merchant({ exchanges: [ { ...exchange, currency: 'XXX' } ] }));

    withMerchant('version-evtaler-exchange-name-none', OPERATOR,
                 'DE*GEF names the EV Taler merchant of the example, its exchange without its name.',
                 `The exchange '${exchange.masterPublicKey}' needs its name, as drivers see it!`,
                 merchant({ exchanges: [ without(exchange, 'name') ] }));

    const keyAt = `${gefAt}/signingKeys/0`;
    refuse({ id: 'version-key-usage-unknown', kind: 'version', basis: OPERATOR,
             description: 'A signing key of DE*GEF names the usage zzz besides its own: a usage POI does not know.',
             reason: `The usage 'zzz' of the public key '${at(qa, `${keyAt}/@id`)}' is unknown`,
             document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, { op: 'add', path: `${keyAt}/usages/-`, value: 'zzz' } ]) });

    // ---- Versions: a charging tariff named by no identification of a charging tariff, {operatorId}*T{suffix} (2): the
    //      tariff DE*GEF*T_AC without its T, by itself and by the EVSE template naming it.
    const tariffAt    = named(`${gefAt}/chargingTariffs/0`, 'DE*GEF*T_AC');
    const templateAt  = named(`${gefAt}/EVSETemplates/0`,   'DE*GEF*ET_AC');
    quoted(SPEC, 'identified as `ChargingTariff_Id`, `{operatorId}*T{suffix}` (`DE*GEF*T_AC`)', 'how a charging tariff is identified');
    if (at(qa, `${templateAt}/chargingTariffId`) !== 'DE*GEF*T_AC')
        fail(`QA.json: the EVSE template ${templateAt} names another charging tariff than DE*GEF*T_AC`);
    refuse({ id: 'version-tariff-id-not-of-its-pattern', kind: 'version', basis: `${SPEC}, 2`,
             description: "DE*GEF names its charging tariff DE*GEF*T_AC 'DE*GEF*AC', without the T of {operatorId}*T{suffix}, and so does its EVSE template DE*GEF*ET_AC.",
             reason: "Invalid charging tariff identification 'DE*GEF*AC'!",
             document: patched('published/QA.json', '', [ { op: 'remove', path: '/eTags' }, { op: 'replace', path: `${tariffAt}/@id`, value: 'DE*GEF*AC' },
                                                          { op: 'replace', path: `${templateAt}/chargingTariffId`, value: 'DE*GEF*AC' } ]) });

    // ---- Versions: a key as the content holds it (2, Written forms; 4.1): its timestamps UTC to the millisecond, its key
    //      the deterministic CBOR of its COSE key. The signing key of DE*GEF for price statements and tariffs with its
    //      notAfter or its key written otherwise. The same instant with an offset, and the same key in CBOR that is not
    //      deterministic, keep the eTags of the version as published: written again, the content has them, read as given
    //      it does not. A notAfter of a date only, or null, is another content: without its eTags, as above.
    const WRITTEN   = `${SPEC}, 2, 4.1`;
    const notAfter  = at(qa, `${keyAt}/notAfter`);
    const coseKey   = Buffer.from(at(qa, `${keyAt}/key`), 'base64');
    quoted(SPEC, '- **Timestamps:** UTC to the millisecond, `yyyy-MM-ddTHH:mm:ss.fffZ`.',            'how a timestamp is written');
    quoted(SPEC, '"key": "<Base64 of the deterministic CBOR of the public COSE key>"',               'how the key of a key is written');
    quoted(SPEC, 'the content holds every value as its entity writes it, read again',               'that the content holds every value as written');
    if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(notAfter) || Date.parse(notAfter) % 86_400_000 === 0)
        fail(`QA.json: the notAfter of the key ${keyAt} is no timestamp of a time of day, written as POI writes it`);
    if (coseKey[0] !== 0xa3 || coseKey[1] !== 0x01)
        fail(`QA.json: the key ${keyAt} is no COSE key of three parameters, kty first`);

    const inZone    = new Date(Date.parse(notAfter) + 2 * 3_600_000).toISOString().replace('Z', '+02:00');
    const notShort  = Buffer.concat([ Buffer.of(0xa3, 0x18, 0x01), coseKey.subarray(2) ]).toString('base64');
    const keyId     = at(qa, `${keyAt}/@id`);
    const written   = (id, description, reason, keepETags, patch) =>
        refuse({ id, kind: 'version', basis: WRITTEN, description, reason,
                 document: patched('published/QA.json', '', [ ...(keepETags ? [] : [ { op: 'remove', path: '/eTags' } ]), ...patch ]) });

    written('version-key-not-after-offset',  `The signing key of DE*GEF for price statements and tariffs names its notAfter, ${notAfter}, as the same instant with the offset +02:00, ${inZone}; the version keeps its eTags.`,
            `The notAfter of the key '${keyId}' must be written as yyyy-MM-ddTHH:mm:ss.fffZ, not '${inZone}'!`,
            true,  [ { op: 'replace', path: `${keyAt}/notAfter`, value: inZone } ]);
    written('version-key-not-after-date',    `The signing key of DE*GEF for price statements and tariffs names its notAfter as a date only, ${notAfter.slice(0, 10)}.`,
            `The notAfter of the key '${keyId}' must be written as yyyy-MM-ddTHH:mm:ss.fffZ, not '${notAfter.slice(0, 10)}'!`,
            false, [ { op: 'replace', path: `${keyAt}/notAfter`, value: notAfter.slice(0, 10) } ]);
    written('version-key-not-after-null',    'The signing key of DE*GEF for price statements and tariffs names its notAfter as null: neither a timestamp nor left out.',
            `The notAfter of the key '${keyId}' must be a text!`,
            false, [ { op: 'replace', path: `${keyAt}/notAfter`, value: null } ]);
    written('version-key-cbor-not-deterministic', 'The signing key of DE*GEF for price statements and tariffs gives its COSE key with the label 1 (kty) in two bytes, 0x18 0x01, not in its shortest form: CBOR that is not deterministic, of the same key; the version keeps its eTags.',
            'deterministic CBOR',
            true,  [ { op: 'replace', path: `${keyAt}/key`, value: notShort } ]);

    // ---- Versions: the content as its entities write it (2, Written forms): what a reader takes and writes otherwise
    //      would be another text than the one hashed - what the content orders out of its ordinal order, the texts of an
    //      ordered list untrimmed, a list the content leaves out where it is empty given empty, a property given as null,
    //      an embedded object naming its JSON-LD context, a text in languages not keyed by the lower-case code of a known
    //      language, a timestamp not UTC to the millisecond; of a key of a party and of an EV Taler merchant and its
    //      exchanges a property POI does not read, a base URL without its scheme or untrimmed, a currency untrimmed. The
    //      head of the run so changed; where it is the version as published, written again, with its eTags - as the
    //      version with the key of D13 -, else without; the reason in the words of WWCP_POI.TS (`notWrittenAsHeld`).
    const HELD        = `${SPEC}, 2`;
    const dotted      = (pointer) => pointer.split('/').slice(1).reduce((path, token) => /^\d+$/.test(token) ? `${path}[${token}]` : path === '' ? token : `${path}.${token}`, '');
    const notHeld     = (pointer, reason) => `'${dotted(pointer)}' is not written as the content holds it: ${reason}!`;
    const ORDER       = 'its elements are in the order the content holds them in';
    const TRIMMED     = 'the texts of its elements are trimmed';
    const LEFT_OUT    = 'a list without elements is left out';
    const NO_VALUE    = 'a property without a value is left out';
    const NO_CONTEXT  = 'embedded, an object names no JSON-LD context';
    const LANGUAGES   = 'a text in languages names each language as Styx writes it, in lower case, with a text';
    const UTC_MS      = 'a timestamp is UTC to the millisecond, yyyy-MM-ddTHH:mm:ss.fffZ';
    const asHeld      = (id, basis, description, reason, keepETags, patch) =>
        refuse({ id, kind: 'version', basis, description, reason,
                 document: patched('published/QA.json', '', [ ...(keepETags ? [] : [ { op: 'remove', path: '/eTags' } ]), ...patch ]) });
    const ordinally   = (texts) => texts.every((text, index) => index === 0 || texts[index - 1] < text);
    const contextOf   = (file, context) => quoted(file, `"${context}";`, `the JSON-LD context ${context}`) && context;
    const KEY_CS      = 'libs/WWCP_POI/WWCP_POI3/DataStructures/POIPublicKey.cs';
    const TALER_CS    = 'libs/WWCP_POI/WWCP_POI3/DataStructures/EVTalerMerchant.cs';
    const pool2       = named(`${gefAt}/chargingPools/1`, 'DE*GEF*P2');
    const bodies      = at(qa, '/conformityAssessmentBodies');
    const signingKeys = at(qa, `${gefAt}/signingKeys`);
    const identities  = at(qa, `${gefAt}/identityKeys`);
    const poolName    = at(qa, `${pool1}/name`);
    const created2    = at(qa, `${pool2}/created`);
    const bsi         = named('/conformityAssessmentBodies/0', 'BSI');

    quoted(SPEC, '- in the ordinal order of their identifications, as written: embedded entities',                      'that embedded entities are in the ordinal order of their identifications');
    quoted(SPEC, 'the `signingKeys` and `identityKeys` of a party;',                                                     'that the keys of a party are in the ordinal order of their identifications');
    quoted(SPEC, '`features`, `parkingRestrictions`, `services`, `standards`, `nutsCodes`',                              'that predefined values are in the ordinal order of their texts');
    quoted(SPEC, 'every other one trimmed; enumerations by their exact names.',                                         'that predefined values are trimmed');
    quoted(SPEC, '- **Absent values** are left out, also empty arrays, texts and objects',                              'that empty arrays and absent values are left out');
    quoted(SPEC, 'also where the object is embedded and its JSON leaves `@context` out',                                 'that an embedded object leaves its JSON-LD context out');
    quoted(SPEC, '- **Texts:** multi-language texts keyed by the lower-case code of a known language',                  'how a text in languages is keyed');
    quoted(SPEC, 'URLs with their scheme (`https://` unless given)',                                                    'that URLs are written with their scheme');
    quoted(SPEC, 'A reader MUST refuse a version written otherwise, as it refuses a new\n  value written otherwise',          'that a reader refuses a version not written as the content holds it');
    quoted(POOL, 'How charging can be paid: `Free`, `Contract`, `Direct`, `Cash`, `CreditCard`, `DebitCard`, `PrepaidCard`, `SMS`', 'which payment options POI knows');
    if (!ordinally(bodies.map(body => body['@id'])) || !ordinally(signingKeys.map(key => key['@id'])) || !ordinally(identities.map(key => key['@id'])) || identities.length < 2)
        fail('QA.json: the conformity assessment bodies, or the keys of DE*GEF, are not in the ordinal order of their identifications, or DE*GEF has fewer than two identity keys');
    if ('paymentOptions' in at(qa, pool2) || 'description' in at(qa, pool2) || JSON.stringify(Object.keys(poolName)) !== '["en"]' || at(qa, `${bsi}/notifiedFor`).length === 0)
        fail('QA.json: DE*GEF*P2 names payment options or a description, DE*GEF*P1 its name in another language than English, or BSI no legislation');
    if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(created2))
        fail(`QA.json: DE*GEF*P2 was created at no timestamp written as POI writes it: ${created2}`);

    // What the content orders, out of its order: written again in the order of the version as published.
    asHeld('version-held-bodies-out-of-order', HELD,
           `The conformity assessment bodies in reverse order, ${bodies.map(body => body['@id']).reverse().join(', ')}: not in the ordinal order of their identifications; the version keeps its eTags.`,
           notHeld('/conformityAssessmentBodies', ORDER),
           true,  [ { op: 'replace', path: '/conformityAssessmentBodies', value: [ ...bodies ].reverse() } ]);
    asHeld('version-held-signing-keys-out-of-order', HELD,
           'The signing keys of DE*GEF in reverse order: not in the ordinal order of their identifications; the version keeps its eTags.',
           notHeld(`${gefAt}/signingKeys`, ORDER),
           true,  [ { op: 'replace', path: `${gefAt}/signingKeys`, value: [ ...signingKeys ].reverse() } ]);
    asHeld('version-held-identity-keys-out-of-order', HELD,
           'The identity keys of DE*GEF in reverse order: not in the ordinal order of their identifications; the version keeps its eTags.',
           notHeld(`${gefAt}/identityKeys`, ORDER),
           true,  [ { op: 'replace', path: `${gefAt}/identityKeys`, value: [ ...identities ].reverse() } ]);
    asHeld('version-held-payment-options-out-of-order', `${HELD}; ${POOL}`,
           'DE*GEF*P2 names the payment options SMS and Cash, in this order: not in the ordinal order of their texts.',
           notHeld(`${pool2}/paymentOptions`, ORDER),
           false, [ { op: 'add', path: `${pool2}/paymentOptions`, value: [ 'SMS', 'Cash' ] } ]);
    asHeld('version-held-payment-options-ordinal', `${HELD}; ${POOL}`,
           'DE*GEF*P2 names the payment options bitcoin and SMS, in this order: alphabetical regardless of case, but in their ordinal order an upper-case letter comes before a lower-case one.',
           notHeld(`${pool2}/paymentOptions`, ORDER),
           false, [ { op: 'add', path: `${pool2}/paymentOptions`, value: [ 'bitcoin', 'SMS' ] } ]);

    // The texts of an ordered list untrimmed, a list given empty, a property given as null.
    asHeld('version-held-payment-options-untrimmed', `${HELD}; ${POOL}`,
           "DE*GEF*P2 names the payment option ' Cash', with a space before it: the content holds it trimmed.",
           notHeld(`${pool2}/paymentOptions`, TRIMMED),
           false, [ { op: 'add', path: `${pool2}/paymentOptions`, value: [ ' Cash' ] } ]);
    asHeld('version-held-payment-options-empty', HELD,
           'DE*GEF*P2 names its payment options as an empty array: the content leaves them out; the version keeps its eTags.',
           notHeld(`${pool2}/paymentOptions`, LEFT_OUT),
           true,  [ { op: 'add', path: `${pool2}/paymentOptions`, value: [] } ]);
    asHeld('version-held-signing-keys-empty', HELD,
           'DE*GEF names its signing keys as an empty array: the content leaves them out.',
           notHeld(`${gefAt}/signingKeys`, LEFT_OUT),
           false, [ { op: 'replace', path: `${gefAt}/signingKeys`, value: [] } ]);
    asHeld('version-held-notified-for-none', HELD,
           'BSI names the legislations it is notified for as an empty array: the content leaves them out.',
           notHeld(`${bsi}/notifiedFor`, LEFT_OUT),
           false, [ { op: 'replace', path: `${bsi}/notifiedFor`, value: [] } ]);
    asHeld('version-held-description-null', HELD,
           'DE*GEF*P2 names its description as null: the content leaves an absent value out; the version keeps its eTags.',
           notHeld(`${pool2}/description`, NO_VALUE),
           true,  [ { op: 'add', path: `${pool2}/description`, value: null } ]);

    // An embedded object naming its JSON-LD context; a text in languages not keyed as the content keys it; a timestamp
    // not UTC to the millisecond.
    asHeld('version-held-key-context', HELD,
           'The signing key of DE*GEF for price statements and tariffs, embedded in its party, names its JSON-LD context; the version keeps its eTags.',
           notHeld(keyAt, NO_CONTEXT),
           true,  [ { op: 'add', path: `${keyAt}/@context`, value: contextOf(KEY_CS, 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/publicKey/v1') } ]);
    asHeld('version-held-name-language-upper-case', HELD,
           `DE*GEF*P1 names its name by the language EN, in upper case: the content keys it by en; the version keeps its eTags.`,
           notHeld(`${pool1}/name`, LANGUAGES),
           true,  [ { op: 'replace', path: `${pool1}/name`, value: { EN: poolName.en } } ]);
    asHeld('version-held-name-language-unknown', HELD,
           'DE*GEF*P1 names its name also in the language xx, which is no known language; the version keeps its eTags.',
           notHeld(`${pool1}/name`, LANGUAGES),
           true,  [ { op: 'add', path: `${pool1}/name/xx`, value: poolName.en } ]);
    asHeld('version-held-name-language-not-a-text', HELD,
           'DE*GEF*P1 names its name also in German, as the number 5: no text; the version keeps its eTags.',
           notHeld(`${pool1}/name`, LANGUAGES),
           true,  [ { op: 'add', path: `${pool1}/name/de`, value: 5 } ]);
    asHeld('version-held-description-language-number', HELD,
           'The roaming network names its description by the language 10, a number: the content keys it by the lower-case code of a language.',
           notHeld('/description', LANGUAGES),
           false, [ { op: 'replace', path: '/description', value: { 10: at(qa, '/description/en') } } ]);
    asHeld('version-held-created-offset', HELD,
           `DE*GEF*P2 was created at ${created2}, given as the same instant with the offset +02:00; the version keeps its eTags.`,
           notHeld(`${pool2}/created`, UTC_MS),
           true,  [ { op: 'replace', path: `${pool2}/created`, value: new Date(Date.parse(created2) + 2 * 3_600_000).toISOString().replace('Z', '+02:00') } ]);

    // A property of a key POI does not read.
    asHeld('version-held-key-property-unread', HELD,
           'The signing key of DE*GEF for price statements and tariffs names the property x, which a key does not have.',
           `The public key '${keyId}' must not name the property 'x'!`,
           false, [ { op: 'add', path: `${keyAt}/x`, value: 1 } ]);

    // The EV Taler merchant of the example, given as the content does not hold it.
    const another     = { masterPublicKey: `0${exchange.masterPublicKey.slice(1)}`, baseURL: 'https://exchange.example.ch/', currency: 'CHF', name: { en: 'Another Exchange' } };
    const ofExchange  = (error) => `Invalid exchange of an EV Taler merchant: ${error}`;
    if (!(another.masterPublicKey < exchange.masterPublicKey) || !evTaler.merchantBaseURL.startsWith('https://') || !exchange.baseURL.startsWith('https://') || JSON.stringify(Object.keys(exchange.name)) !== '["en"]')
        fail(`${OPERATOR}: the example of an EV Taler merchant is no longer one these vectors change`);

    const heldMerchant = (id, description, reason, changed) =>
        asHeld(id, `${HELD}; ${OPERATOR}`, `DE*GEF names the EV Taler merchant of the example, ${description}.`, reason, false, merchant(changed));

    heldMerchant('version-held-evtaler-context',              'naming its JSON-LD context, embedded in its operator',
                 notHeld(`${gefAt}/evTaler`, NO_CONTEXT),                       { '@context': contextOf(TALER_CS, 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/evTalerMerchant/v1') });
    heldMerchant('version-held-evtaler-exchange-context',     'its exchange naming its JSON-LD context, embedded in the merchant',
                 notHeld(`${gefAt}/evTaler/exchanges/0`, NO_CONTEXT),           { exchanges: [ { ...exchange, '@context': contextOf(TALER_CS, 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/evTalerExchange/v1') } ] });
    heldMerchant('version-held-evtaler-exchanges-out-of-order', `accepting also the exchange ${another.masterPublicKey} in CHF, after the one of the example: not in the ordinal order of their master public keys`,
                 notHeld(`${gefAt}/evTaler/exchanges`, ORDER),                  { exchanges: [ exchange, another ] });
    heldMerchant('version-held-evtaler-exchange-name-language', 'the name of its exchange by the language EN, in upper case',
                 notHeld(`${gefAt}/evTaler/exchanges/0/name`, LANGUAGES),       { exchanges: [ { ...exchange, name: { EN: exchange.name.en } } ] });
    heldMerchant('version-held-evtaler-property-unread',      'naming the property x, which a merchant does not have',
                 "The EV Taler merchant must not name the property 'x'!",      { x: 1 });
    heldMerchant('version-held-evtaler-exchange-property-unread', 'its exchange naming the property x, which an exchange does not have',
                 ofExchange(`The exchange '${exchange.masterPublicKey}' must not name the property 'x'!`), { exchanges: [ { ...exchange, x: 1 } ] });

    const noScheme    = evTaler.merchantBaseURL.replace('https://', '');
    heldMerchant('version-held-evtaler-merchant-url-no-scheme', `its merchant base URL without its scheme, ${noScheme}`,
                 `The merchant base URL '${noScheme}' is written as '${evTaler.merchantBaseURL}'!`, { merchantBaseURL: noScheme });
    heldMerchant('version-held-evtaler-merchant-url-untrimmed', 'its merchant base URL with a space before and after it',
                 `The merchant base URL ' ${evTaler.merchantBaseURL} ' is written as '${evTaler.merchantBaseURL}'!`, { merchantBaseURL: ` ${evTaler.merchantBaseURL} ` });
    heldMerchant('version-held-evtaler-exchange-url-no-scheme', `the base URL of its exchange without its scheme, ${exchange.baseURL.replace('https://', '')}`,
                 ofExchange(`The base URL '${exchange.baseURL.replace('https://', '')}' of the exchange '${exchange.masterPublicKey}' is written as '${exchange.baseURL}'!`),
                 { exchanges: [ { ...exchange, baseURL: exchange.baseURL.replace('https://', '') } ] });
    heldMerchant('version-held-evtaler-exchange-currency-untrimmed', `the currency of its exchange with a space before it, ' ${exchange.currency}'`,
                 ofExchange(`The currency ' ${exchange.currency}' of the exchange '${exchange.masterPublicKey}' is written as '${exchange.currency}'!`),
                 { exchanges: [ { ...exchange, currency: ` ${exchange.currency}` } ] });

    readAsWWCP_POI3({ qa, named, patched, refuse, notHeld, gefAt, pool1, pool2, tariffAt, templateAt, bsi, DOCS, HELD, ORDER });

    // ---- Checkpoint proofs (10.4).
    const proof4 = jsonRun('published/QA-proof-revision-4.json');
    refuse({ id: 'checkpointProof-index',     kind: 'checkpointProof', basis: `${SPEC}, 10.4`, description: 'Another position of the commit in the checkpoint.',                                  document: patched('published/QA-proof-revision-4.json', '', [ { op: 'replace', path: '/@index', value: proof4['@index'] === 0 ? 1 : 0 } ]), checkpoint: { file: 'published/QA-checkpoint-0.json', pointer: '' } });
    refuse({ id: 'checkpointProof-path',      kind: 'checkpointProof', basis: `${SPEC}, 10.4`, description: 'Another node on the audit path.',                                                     document: patched('published/QA-proof-revision-4.json', '', [ { op: 'replace', path: '/@auditPath/0', value: '0'.repeat(64) } ]), checkpoint: { file: 'published/QA-checkpoint-0.json', pointer: '' } });
    refuse({ id: 'checkpointProof-revision',  kind: 'checkpointProof', basis: `${SPEC}, 10.4`, description: 'Another revision in the leaf.',                                                        document: patched('published/QA-proof-revision-4.json', '', [ { op: 'replace', path: '/leaf/revision', value: proof4.leaf.revision + 1 } ]), checkpoint: { file: 'published/QA-checkpoint-0.json', pointer: '' } });
    refuse({ id: 'checkpointProof-other',     kind: 'checkpointProof', basis: `${SPEC}, 10.4`, description: 'The proof against another checkpoint.',                                               document: patched('published/QA-proof-revision-4.json', '', []), checkpoint: { file: 'published/QA-checkpoint-1.json', pointer: '' } });

    // ---- Station proofs (8.4, 8.5): the root, the attestations, their validity.
    const stationProof = 'published/QA-DE-GEF-E1-1-proof.json';
    const sp           = jsonRun(stationProof);
    const signedAt     = sp.attestations.map(attestation => Date.parse(attestation.signedAt)).sort((a, b) => a - b)[0];
    const statedAt     = [ sp.roamingNetwork.operator.keyStatement, ...sp.roamingNetwork.operator.signingKeyCertificates ].map(signed => Date.parse(signed.signedAt)).sort((a, b) => b - a)[0];
    if (!(statedAt < signedAt - 1000))
        fail(`${stationProof}: the key statement and the certificates are not signed a second before the attestations`);
    const validUntil   = sp.attestations.map(attestation => Date.parse(attestation.validUntil)).sort((a, b) => b - a)[0];
    const iso          = (ms) => new Date(ms).toISOString();
    const proofVector  = (id, description, patch, more = {}) => refuse({ id, kind: 'stationProof', basis: `${SPEC}, 8.4, 8.5`, description, document: patched(stationProof, '', patch), trustAnchor: 'published/QA-trustAnchor-mldsa.txt', at: AT, evseId: 'DE*GEF*E1*1', ...more });

    proofVector('stationProof-expired',        'After every attestation ended (validUntil).',                                                        [], { at: iso(validUntil + 1000) });
    proofVector('stationProof-before-signed',  'A second before every attestation was signed, the key statement and the certificates valid: an attestation of the future is no attestation now (csharp-review 7).', [], { at: iso(signedAt - 1000), basis: `${SPEC}, 8.5, Validity; csharp-review 7` });
    proofVector('stationProof-other-anchor',   'Against the trust anchor of epoch 1, whose identity keys did not sign the key statement of epoch 2.', [], { trustAnchor: 'published/QA-trustAnchor.txt' });
    proofVector('stationProof-entity',         'An EVSE the proof gives completely changed: the proof leads to another root.',                       [ { op: 'replace', path: pathOfEVSE(sp, 'DE*GEF*E1*1') + '/maxPower', value: 999999 } ]);
    proofVector('stationProof-signature',      'The value of every attestation changed.',                                                            sp.attestations.map((attestation, index) => ({ op: 'replace', path: `/attestations/${index}/value`, value: attestation.value.slice(0, 8) + (attestation.value[8] === 'A' ? 'B' : 'A') + attestation.value.slice(9) })));
    quoted(SPEC, 'An attestation counts for the proof only where it names the', 'that an attestation counts for the commit and revision it names only');
    proofVector('stationProof-revision',       'Another revision than its attestations name, the commit the same.',                                   [ { op: 'replace', path: '/revision', value: sp.revision + 1 } ]);
    proofVector('stationProof-commit',         'Another commit than its attestations name.',                                                          [ { op: 'replace', path: '/commitId', value: '0'.repeat(128) } ]);
    proofVector('stationProof-no-attestations','Without attestations.',                                                                              [ { op: 'replace', path: '/attestations', value: [] } ]);
    proofVector('stationProof-one-holder',     'With the attestation of one holder only, where the quorum takes more.',                             [ { op: 'replace', path: '/attestations', value: [ sp.attestations[0] ] } ]);

    // ---- Price statements (12.1): their signature covers what they say.
    refuse({ id: 'priceStatement-price',       kind: 'priceStatement', basis: `${SPEC}, 12.1`, description: 'Another price, the signature not.',    document: patched('published/QA-checkpoint-4-priceStatements.json', '/0', [ { op: 'replace', path: '/priceStatus/prices/0/elements/0/priceComponents/0/price', value: 0.01 } ]), keysFrom: { file: 'published/QA-checkpoint-4-snapshot.json', pointer: '/roamingNetwork' } });
    refuse({ id: 'priceStatement-sequence',    kind: 'priceStatement', basis: `${SPEC}, 12.1`, description: 'Another sequence.',                     document: patched('published/QA-checkpoint-4-priceStatements.json', '/0', [ { op: 'replace', path: '/sequence', value: 7 } ]), keysFrom: { file: 'published/QA-checkpoint-4-snapshot.json', pointer: '/roamingNetwork' } });
    refuse({ id: 'priceStatement-entity',      kind: 'priceStatement', basis: `${SPEC}, 12.1`, description: 'Another EVSE.',                         document: patched('published/QA-checkpoint-4-priceStatements.json', '/0', [ { op: 'replace', path: '/entityId', value: 'DE*GEF*E1*2' } ]), keysFrom: { file: 'published/QA-checkpoint-4-snapshot.json', pointer: '/roamingNetwork' } });

    // ---- A price status is read before the signature is looked at (12.1): a statement whose price status is none is no
    //      price statement. No patch here leaves the signature valid, so each vector names the words both refuse it in,
    //      those of WWCP_POI3's ChargingPrices and ChargingTariffPrices, as WWCP_POI.TS reads it since 80afec7.
    {
        const STATEMENTS = 'published/QA-checkpoint-4-priceStatements.json';
        const statement  = at(jsonRun(STATEMENTS), '/0');
        const price      = statement.priceStatus.prices[0];
        const P0         = '/priceStatus/prices/0';
        if (Object.keys(statement.priceStatus).join() !== 'prices' || statement.priceStatus.prices.length !== 1 || Object.keys(price).join() !== 'chargingTariffId,elements' ||
            price.chargingTariffId !== 'DE*GEF*T_DC' || price.elements.length !== 1 || price.elements[0].priceComponents.length !== 1)
            fail(`${STATEMENTS}/0: no price status of the prices of DE*GEF*T_DC alone, of one element of one price component`);
        quoted(SPEC, 'refused before its signature is looked at, and so is one without a price status or with one that is none:', 'that a statement without a price status, or with one that is none, is refused');
        quoted(SPEC, 'a price status holds its `prices`, an array, and no other property;',                                       'what a price status holds');
        quoted(SPEC, 'the prices of a charging tariff hold its `chargingTariffId` and its `elements`, and no other property;',     'what the prices of a charging tariff hold');
        quoted(SPEC, 'suffix without case and `*`: `DE*GEF*T_dc` names `DE*GEF*T_DC`;',                                           'that a price status names each charging tariff once');
        quoted(SPEC, 'the `elements` are at least one, each a JSON object read as those of a charging tariff, with at least one price', 'what the elements of the prices of a charging tariff are');
        const PRICES_CONTEXT = quoted(SPEC, 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/chargingPrices/v1',       'the JSON-LD context of a price status');
        const TARIFF_CONTEXT = quoted(SPEC, 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/chargingTariffPrices/v1', 'the JSON-LD context of the prices of a charging tariff');
        const invalid = (error) => `Invalid price status of the price statement: ${error}`;
        const status  = (id, description, reason, patch) =>
            refuse({ id, kind: 'priceStatement', basis: `${SPEC}, 12.1, 1.1`, description, reason, document: patched(STATEMENTS, '/0', patch), keysFrom: { file: 'published/QA-checkpoint-4-snapshot.json', pointer: '/roamingNetwork' } });

        status('priceStatement-without-price-status',      'Without its price status.',
               'A price statement needs its price status!',                                                                 [ { op: 'remove',  path: '/priceStatus' } ]);
        status('priceStatement-prices-not-an-array',       'Its prices not an array, but the prices of DE*GEF*T_DC alone.',
               invalid('A price status must be a JSON object { prices: [ { chargingTariffId, elements }, … ] }!'),          [ { op: 'replace', path: '/priceStatus/prices', value: price } ]);
        status('priceStatement-status-unknown-property',   'A price status naming a currency, which it does not hold.',
               invalid("Unknown property 'currency' of a price status!"),                                                   [ { op: 'add',     path: '/priceStatus/currency', value: 'EUR' } ]);
        status('priceStatement-status-context',            'A price status naming the JSON-LD context of the prices of a charging tariff.',
               invalid(`The JSON-LD context of a price status must be '${PRICES_CONTEXT}'!`),                               [ { op: 'add',     path: '/priceStatus/@context', value: TARIFF_CONTEXT } ]);
        status('priceStatement-tariff-prices-not-an-object', 'The prices of DE*GEF*T_DC as its identification alone.',
               invalid('The prices of a charging tariff must be a JSON object { chargingTariffId, elements }!'),            [ { op: 'replace', path: P0, value: 'DE*GEF*T_DC' } ]);
        status('priceStatement-tariff-prices-unknown-property', 'The prices of DE*GEF*T_DC naming a currency, which they do not hold.',
               invalid("Unknown property 'currency' of the prices of a charging tariff!"),                                  [ { op: 'add',     path: `${P0}/currency`, value: 'EUR' } ]);
        status('priceStatement-tariff-prices-context',     'The prices of DE*GEF*T_DC naming the JSON-LD context of a price status.',
               invalid(`The JSON-LD context of the prices of a charging tariff must be '${TARIFF_CONTEXT}'!`),              [ { op: 'add',     path: `${P0}/@context`, value: PRICES_CONTEXT } ]);
        status('priceStatement-tariff-id-not-of-its-pattern', "The prices of DE*GEF*T_DC naming it 'DE*GEF*DC', without the T of {operatorId}*T{suffix} (D16).",
               invalid("The prices of a charging tariff need a valid 'chargingTariffId'!"),                                 [ { op: 'replace', path: `${P0}/chargingTariffId`, value: 'DE*GEF*DC' } ]);
        status('priceStatement-tariff-elements-empty',     'The prices of DE*GEF*T_DC without elements.',
               invalid("The prices of the charging tariff 'DE*GEF*T_DC' need their elements as a JSON array, at least one!"), [ { op: 'replace', path: `${P0}/elements`, value: [] } ]);
        status('priceStatement-tariff-element-not-an-object', 'An element of the prices of DE*GEF*T_DC that is a text.',
               invalid('A charging tariff element must be a JSON object!'),                                                 [ { op: 'replace', path: `${P0}/elements/0`, value: 'ENERGY' } ]);
        status('priceStatement-tariff-element-without-price-components', 'An element of the prices of DE*GEF*T_DC without price components.',
               invalid('A charging tariff element needs at least one price component!'),                                   [ { op: 'replace', path: `${P0}/elements/0/priceComponents`, value: [] } ]);

        // The elements written as a charging tariff holds them, as a version holds those of a tariff (12.1, 2), in the
        // words of WWCP_POI3's written form (FirstNotWritten).
        quoted(SPEC, 'the `elements` are written as a charging tariff holds them (section 2, "Written forms"), as a version holds the', 'that the elements of a price status are written as a charging tariff holds them');
        const ELEMENT_CONTEXT = quoted('libs/WWCP_POI/WWCP_POI3/RoamingNetwork/ChargingTariff/ChargingTariffElement.cs', 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/chargingTariffElement/v1', 'the JSON-LD context of a charging tariff element');
        const E0      = `${P0}/elements/0`;
        const written = (path, reason) => invalid(`'${path}' of the prices of the charging tariff 'DE*GEF*T_DC' is not written as a charging tariff holds it: ${reason}!`);
        status('priceStatement-tariff-element-restriction-unknown', 'An element of the prices of DE*GEF*T_DC from 08:00 and to a state of charge of at most 80 %, maxStateOfCharge, a restriction no charging tariff has: a reader not knowing it would price every session from 08:00 so.',
               written('elements[0].restrictions.maxStateOfCharge', 'the content leaves it out'),                          [ { op: 'add',     path: `${E0}/restrictions`, value: { startTime: '08:00', maxStateOfCharge: 80 } } ]);
        status('priceStatement-tariff-element-property-unknown', 'An element of the prices of DE*GEF*T_DC naming the property x, which an element of a charging tariff does not have.',
               written('elements[0].x', 'the content leaves it out'),                                                      [ { op: 'add',     path: `${E0}/x`, value: 1 } ]);
        status('priceStatement-tariff-price-component-property-unknown', 'A price component of the prices of DE*GEF*T_DC naming the property x, which a price component does not have.',
               written('elements[0].priceComponents[0].x', 'the content leaves it out'),                                   [ { op: 'add',     path: `${E0}/priceComponents/0/x`, value: 1 } ]);
        status('priceStatement-tariff-element-restriction-number-text', 'An element of the prices of DE*GEF*T_DC from a power of 11, given as the text "11", which a charging tariff holds as a number.',
               written('elements[0].restrictions.minPower', "the content holds it as '11'"),                               [ { op: 'add',     path: `${E0}/restrictions`, value: { minPower: '11' } } ]);
        status('priceStatement-tariff-element-days-out-of-order', 'An element of the prices of DE*GEF*T_DC on Tuesdays and Mondays, in this order, which a charging tariff holds Monday first.',
               written('elements[0].restrictions.daysOfWeek', 'its elements are in the order the content holds them in'), [ { op: 'add',     path: `${E0}/restrictions`, value: { daysOfWeek: [ 'TUESDAY', 'MONDAY' ] } } ]);
        status('priceStatement-tariff-element-context', 'An element of the prices of DE*GEF*T_DC naming the JSON-LD context of a charging tariff element, which an embedded element does not.',
               written('elements[0]', 'embedded, an object names no JSON-LD context'),                                     [ { op: 'add',     path: `${E0}/@context`, value: ELEMENT_CONTEXT } ]);
        status('priceStatement-tariff-named-twice',        'The prices of DE*GEF*T_DC given twice.',
               invalid("A price status must name the charging tariff 'DE*GEF*T_DC' only once!"),                            [ { op: 'add',     path: '/priceStatus/prices/-', value: price } ]);
        status('priceStatement-tariff-named-twice-spelling', 'The prices of DE*GEF*T_DC given twice, the second time as DE*GEF*T_dc: one charging tariff.',
               invalid("A price status must name the charging tariff 'DE*GEF*T_dc' only once!"),                            [ { op: 'add',     path: '/priceStatus/prices/-', value: { ...price, chargingTariffId: 'DE*GEF*T_dc' } } ]);
    }

    // ---- A price statement names its entity as the roaming network does (12.1): identifications equal without "*",
    //      whitespace and case are one entity with one chain. The statement of the evidence of example A10, made against
    //      revision 13, checked as each implementation has it: taken by a history started from the snapshot of checkpoint
    //      4 of revision 13 (a server, WWCP_POI3), and by a client with the proof of its station the evidence holds,
    //      verified against the trust anchor of epoch 1 when charging began (WWCP_POI.TS).
    quoted(SPEC, 'case, as `DE*GEF*E11` and `DE*GEF*E1*1`, are one entity with one chain; a statement naming it in another', 'that a statement names its entity as the roaming network does');

    const EVIDENCE        = 'driver/evidence-DE_GEF_E1_1.json';
    const CP4             = 'published/QA-checkpoint-4.json';
    const CP4_STATEMENTS  = 'published/QA-checkpoint-4-priceStatements.json';
    const CP4_SNAPSHOT    = 'published/QA-checkpoint-4-snapshot.json';
    const evidence        = jsonRun(EVIDENCE);
    const cp4             = rawRun(CP4);

    if (evidence.priceStatements[0].entityId !== 'DE*GEF*E1*1' || evidence.priceStatements[0].after !== cp4['@id'] ||
        evidence.chargingStationProof.revision !== 13 || jsonRun(CP4_SNAPSHOT).commit.revision !== 13 || jsonRun(CP4_SNAPSHOT).commit['@id'] !== cp4.commitId)
        fail(`${EVIDENCE}: no longer the statement of DE*GEF*E1*1 made after checkpoint 4, of revision 13, with a proof of revision 13`);

    const ofEntity = { snapshot: { file: CP4_SNAPSHOT, pointer: '' }, stationProof: { file: EVIDENCE, pointer: '/chargingStationProof' }, trustAnchor: 'published/QA-trustAnchor.txt', at: evidence.chargingStarted };

    refuse({ id: 'priceStatement-entity-spelling', kind: 'entityPriceStatement', basis: `${SPEC}, 12.1`, description: 'The price statement of the evidence naming its EVSE DE*GEF*E1*1 as DE*GEF*E11, equal to it without "*": one entity, named as the roaming network names it.',
             reason: "The price statement names the EVSE 'DE*GEF*E1*1' as 'DE*GEF*E11': it has to name it as the roaming network does!",
             document: patched(EVIDENCE, '/priceStatements/0', [ { op: 'replace', path: '/entityId', value: 'DE*GEF*E11' } ]), ...ofEntity });

    // ---- The price statements a checkpoint names (12.3): no two of one entity, in any spelling, and sequence that differ.
    //      Checkpoint 4 of the run, its tree of statements calculated anew over its three and one more - the first of
    //      DE*GEF*E1*1 named DE*GEF*E11, or with another price -, its @id with it; checked as each implementation has it:
    //      taken along with the checkpoint by a history started from the snapshot of checkpoint 4, commit and checkpoint
    //      signatures unchecked (WWCP_POI3), and checked against the checkpoint (WWCP_POI.TS). The second statement of a
    //      split view is never signed: both refuse it before they look at its signature.
    quoted(SPEC, 'valid at `signedAt`, and no two of one entity (12.1) and sequence differ.', 'that a checkpoint names no two statements of one entity and sequence that differ');
    quoted(SPEC, 'identifications, then of their sequences; a leaf is the 32 bytes of the digest of a statement. It is part', 'the leaves of the tree of the price statements of a checkpoint');

    const digestOf     = (statement) => sha256(utf8(canonical({ '@context': CONTEXTS.priceStatement, ...without(statement, 'value') })));
    const statementsIn = (statements) => statements.map(statement => ({ statement, digest: digestOf(statement) })).
                                                    sort((left, right) => (left.statement.entityType < right.statement.entityType ? -1 : left.statement.entityType > right.statement.entityType ? 1 : 0) ||
                                                                          (left.statement.entityId   < right.statement.entityId   ? -1 : left.statement.entityId   > right.statement.entityId   ? 1 : 0) ||
                                                                          (numberOf(left.statement.sequence) - numberOf(right.statement.sequence)) ||
                                                                          (left.digest < right.digest ? -1 : 1));
    const treeOf       = (statements) => ({ '@merkleRoot': mth(hashOf('sha256'), statementsIn(statements).map(({ digest }) => Buffer.from(digest, 'hex'))).toString('hex'), '@size': statements.length });
    const statements4  = rawRun(CP4_STATEMENTS);

    anchor('the tree of the price statements of checkpoint 4', JSON.stringify(treeOf(statements4)), JSON.stringify({ '@merkleRoot': cp4.priceStatements['@merkleRoot'], '@size': numberOf(cp4.priceStatements['@size']) }));
    anchor('the identification of checkpoint 4', checkpointIdOf(cp4, 'sha256'), cp4['@id']);

    const splitView = (id, description, reason, forged) => {
        // The statement as the vector writes it and every reader reads it: JSON, its numbers written as JavaScript writes them.
        const written  = parseRaw(JSON.stringify(forged));
        const tree     = treeOf([ ...statements4, written ]);
        const ordered  = statementsIn([ ...statements4, written ]).map(({ digest }) => digest);
        if (ordered.indexOf(digestOf(statements4[0])) > ordered.indexOf(digestOf(written)))
            fail(`${id}: the second statement of the split view is not checked after the first one`);
        refuse({ id, kind: 'checkpointPriceStatements', basis: `${SPEC}, 12.3`, description, reason,
                 document: patched(CP4, '', [ { op: 'replace', path: '/priceStatements', value: tree }, { op: 'replace', path: '/@id', value: checkpointIdOf({ ...cp4, priceStatements: tree }, 'sha256') } ]),
                 priceStatements: patched(CP4_STATEMENTS, '', [ { op: 'add', path: '/-', value: forged } ]),
                 snapshot: { file: CP4_SNAPSHOT, pointer: '' } });
    };

    const first4       = jsonRun(CP4_STATEMENTS)[0];
    if (first4.entityId !== 'DE*GEF*E1*1' || first4.sequence !== 0)
        fail(`${CP4_STATEMENTS}#/0: no longer the first statement of DE*GEF*E1*1`);

    splitView('checkpoint-price-statements-spelling', 'Checkpoint 4 naming, besides the first statement of DE*GEF*E1*1, one of DE*GEF*E11 of the same sequence: one entity in two spellings, two statements of one sequence.',
              "names two price statements 0 of the EVSE 'DE*GEF*E11'", { ...first4, entityId: 'DE*GEF*E11' });

    // Another price, its digest after the one of the first statement: of one entity and sequence, the statements are in
    // the order of their digests, and the first one of the two is checked before the second one.
    const otherPrice   = [ 0.49, 0.59, 0.69, 0.79, 0.89, 0.99 ].map(price => { const forged = structuredClone(first4); forged.priceStatus.prices[0].elements[0].priceComponents[0].price = price; return forged; }).
                             find(forged => digestOf(parseRaw(JSON.stringify(forged))) > digestOf(rawRun(CP4_STATEMENTS)[0]) && JSON.stringify(forged) !== JSON.stringify(first4)) ?? fail('no other price of a digest after the first statement');
    splitView('checkpoint-price-statements-other-price', `Checkpoint 4 naming, besides the first statement of DE*GEF*E1*1, another one of the same sequence at ${otherPrice.priceStatus.prices[0].elements[0].priceComponents[0].price} €/kWh: two statements of one sequence.`,
              "names two price statements 0 of the EVSE 'DE*GEF*E1*1'", otherPrice);

    // ---- Trust anchors (8.6): the text of the QR code.
    const qr = readRun('published/QA-trustAnchor.txt').trim();
    refuse({ id: 'trustAnchor-prefix',         kind: 'trustAnchor', basis: `${SPEC}, 8.6`, description: 'Another version of the QR code.',        text: qr.replace('WWCP/TA-2:', 'WWCP/TA-1:') });
    refuse({ id: 'trustAnchor-truncated',      kind: 'trustAnchor', basis: `${SPEC}, 8.6`, description: 'The QR code without its last characters.', text: qr.slice(0, -3) });
    refuse({ id: 'trustAnchor-base45',         kind: 'trustAnchor', basis: `${SPEC}, 8.6`, description: 'A character that is no Base45.',           text: qr.slice(0, 20) + 'a' + qr.slice(21) });

    return vectorFile(
        `WWCP POI 3 SPECIFICATION.md (libs/WWCP_POI); documents of test-vectors/runs/${RUN}`,
        'Documents an implementation must refuse: a document of the run with a JSON patch (RFC 6902, add/replace/remove) applied, a time it is checked at, or a text. "kind" says what is checked; "basis" where the specification says so, or "(proposed)" where it does not say so yet.',
        { run: `runs/${RUN}`, vectors: ids(vectors, 'refusals') });

}

/** The JSON pointer of an EVSE the proof gives completely. */
function pathOfEVSE(proof, evseId) {
    const search = (node, path) => {
        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) { const found = search(node[i], `${path}/${i}`); if (found) return found; }
            return undefined;
        }
        if (node === null || typeof node !== 'object')
            return undefined;
        if (node['@id'] === evseId && path.includes('/EVSEs/'))
            return path;
        for (const [ key, value ] of Object.entries(node)) { const found = search(value, `${path}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`); if (found) return found; }
        return undefined;
    };
    return search(proof, '') ?? fail(`the proof gives no EVSE ${evseId} completely`);
}


// =====================================================================================================================
//  7. Small histories the generator signs: what a history takes, and what it refuses
// =====================================================================================================================
//
// The keys of the frozen run are random and private: nothing it holds can be changed and signed anew. These histories the
// generator makes itself, of the roaming network rn1 of section 6, its operator DE*RNO holding the quorum of section 6
// (the identity keys of Alpha and Beta, and their signing keys), and parties of keys of their own. Ed25519 and Ed448 sign
// deterministically, ES256 with the nonces of RFC 6979: every byte below is the same each time. What it calculates of
// them - deterministic CBOR, the effective tree, identifications, signature inputs - it first calculates of the frozen run
// and of SPECIFICATION.md, against what is written there (the anchors); a history both implementations take is calculated
// by both as by the generator, and one they refuse, its control taken, is refused for what it changes.

const CONTEXTS = {
    changeSet:            CONTEXT + 'changeSet/v3',
    commit:               CONTEXT + 'commit/v3',
    commitSignature:      CONTEXT + 'commitSignature/v1',
    checkpoint:           CONTEXT + 'checkpoint/v1',
    checkpointSignature:  CONTEXT + 'checkpointSignature/v1',
    keyStatement:         CONTEXT + 'keyStatement/v3',
    certificate:          CONTEXT + 'signingKeyCertificate/v2',
    priceStatement:       CONTEXT + 'priceStatement/v1',
    attestation:          CONTEXT + 'attestation/v1',
};


// ---- Identifications and signature inputs (4, 5.1, 5.4, 8.6, 10.1, 10.2) -----------------------------------------------

const IDENTIFICATION_LENGTHS = { sha256: 64, sha384: 96, sha512: 128 };

const identificationHashOf = (id) => Object.keys(IDENTIFICATION_LENGTHS).find(hash => IDENTIFICATION_LENGTHS[hash] === id.length) ?? fail(`no identification: ${id}`);

const digestHex = (hash, text) => createHash(hash).update(utf8(text)).digest('hex');

/** The @id of a change set (4): the SHA-256 of its canonical JSON with its @context, without @id and signatures. */
const changeSetIdOf = (changeSet) => sha256(utf8(canonical({ ...without(changeSet, '@id', '@context', 'signatures'), '@context': CONTEXTS.changeSet })));

/** The @id of a commit (5.1): the digest, with the identification hash of its epoch, of its content. */
const commitIdOf = (commit, hash) => digestHex(hash, canonical({ ...without(commit, '@id', '@context', 'signatures', 'changeSet'), '@context': CONTEXTS.commit,
                                                                 ...(commit.changeSet === undefined ? {} : { changeSet: without(commit.changeSet, '@context', 'signatures') }) }));

/** The @id of a checkpoint (10.1): the digest of the checkpoint with its @context, without @id and signatures. */
const checkpointIdOf = (checkpoint, hash) => digestHex(hash, canonical({ ...without(checkpoint, '@id', '@context', 'signatures'), '@context': CONTEXTS.checkpoint }));

/** A leaf of the commits of a checkpoint (10.1). */
const commitLeafOf = (commit) => utf8(canonical({ commitId: commit['@id'], eTags: commit.eTags, revision: commit.revision }));

/** The signature input of a change set (4): the change set without its signatures and @context, with its @id. */
const changeSetSignatureInput = (changeSet, { algorithm, keyId }) => canonical({ '@context': CONTEXTS.changeSet, algorithm, keyId, changeSet: without(changeSet, '@context', 'signatures') });

/** The signature input of a commit or a checkpoint in a role (5.4, 10.2): the signature without its value, and what it signs. */
const roleSignatureInput = (context, signature, name, signed) => canonical({ '@context': context, ...without(signature, 'value'), [name]: signed });

/** A commit as its signatures sign it: with its @context, its @id and the signatures of its change set (5.4). */
const commitAsSigned = (commit) => ({ ...without(commit, 'signatures'), '@context': CONTEXTS.commit, ...(commit.changeSet === undefined ? {} : { changeSet: without(commit.changeSet, '@context') }) });

/** A checkpoint as its signatures sign it: with its @context and @id (10.2). */
const checkpointAsSigned = (checkpoint) => ({ ...without(checkpoint, 'signatures'), '@context': CONTEXTS.checkpoint });

/** The signature input of a key statement (8.6) and of the certificate of a signing key (8.6). */
const keyStatementSignatureInput = (statement, { algorithm, keyId }) => canonical({ '@context': CONTEXTS.keyStatement, algorithm, keyId, ...without(statement, 'signatures') });
const certificateSignatureInput  = (certificate)                     => canonical({ '@context': CONTEXTS.certificate, ...without(certificate, 'value') });

/** The signature input of an attestation (8.5): the attestation without its value, with its @context. */
const attestationSignatureInput  = (attestation)                     => canonical({ '@context': CONTEXTS.attestation, ...without(attestation, 'value') });


// ---- The anchors: what section 7 calculates, calculated first of the frozen run --------------------------------------

/** Every JSON document of the frozen run, read with its numbers as written. */
const runDocuments = () => walk(RUN_DIR).map(runFile).filter(file => file.endsWith('.json')).map(file => ({ file, json: rawRun(file) }));

function anchorTheRun(history) {

    const documentOf = (vector) => at(rawRun(vector.file), vector.pointer);

    // Deterministic CBOR and the ETags of the content: of every version of the run, as its commit names them; the effective
    // tree of the genesis, whose effective content is its content.
    for (const vector of history.versions) {
        const content = without(documentOf(vector), 'eTags');
        anchor(`the json ETag of ${vector.id}`, etagText(eTagsOf(content)[0], vector.id), vector.eTags[0]);
        anchor(`the cbor ETag of ${vector.id}`, etagText(eTagsOf(content)[1], vector.id), vector.eTags[1]);
        if (vector.file === 'published/QA-genesis.json')
            anchor(`the effective tree of ${vector.id}`, etagText(eTagsOf(content)[2], vector.id), vector.eTags[2]);
    }

    // Identifications: of every commit and its change set, of every checkpoint and the tree of its commits.
    const commits = new Map();

    for (const vector of history.commits) {
        const commit = documentOf(vector);
        anchor(`the identification of ${vector.id}`, commitIdOf(commit, identificationHashOf(commit['@id'])), vector.commitId);
        if (commit.changeSet !== undefined && !commit.changeSet['@id'].startsWith('merge-'))
            anchor(`the identification of the change set of ${vector.id}`, changeSetIdOf(commit.changeSet), commit.changeSet['@id']);
        commits.set(commit['@id'], commit);
    }

    const checkpoints = history.checkpoints.map(vector => ({ vector, checkpoint: documentOf(vector) }));

    for (const { vector, checkpoint } of checkpoints) {

        const hash  = identificationHashOf(checkpoint['@id']);
        anchor(`the identification of ${vector.id}`, checkpointIdOf(checkpoint, hash), vector.checkpointId);

        // Its commits: back from its commit to the commit of the checkpoint before it, or to the genesis of its epoch.
        const before   = checkpoints.find(other => other.checkpoint['@id'] === checkpoint.previousId)?.checkpoint;
        const own      = [];
        for (let commit = commits.get(checkpoint.commitId); commit !== undefined && commit['@id'] !== before?.commitId; commit = commits.get(commit.parentIds?.[0]))
            own.push(commit);
        if (checkpoint.final === true && before?.commitId === checkpoint.commitId)
            own.push(commits.get(checkpoint.commitId));
        own.sort((left, right) => numberOf(left.revision) - numberOf(right.revision) || (left['@id'] < right['@id'] ? -1 : 1));
        anchor(`the tree of the commits of ${vector.id}`, mth(hashOf(hash), own.map(commitLeafOf)).toString('hex') + '/' + own.length,
               `${checkpoint.commits['@merkleRoot']}/${numberOf(checkpoint.commits['@size'])}`);

    }

    // Signature inputs: every signature of the run node:crypto verifies (ECDSA, Ed25519, Ed448; not ML-DSA) verifies with
    // its key over the input as section 7 writes it.
    const keys = new Map();
    const visit = (value) => {
        if (Array.isArray(value))
            value.forEach(visit);
        else if (value !== null && typeof value === 'object' && value[RAW] === undefined) {
            if (typeof value['@id'] === 'string' && typeof value.key === 'string')
                keys.set(value['@id'], value.key);
            Object.values(value).forEach(visit);
        }
    };
    const documents = runDocuments();
    documents.forEach(({ json }) => visit(json));

    let verified = 0;
    const check = (what, { algorithm, keyId, value }, input) => {
        const result = verifiesWith(algorithm, keys.get(keyId) ?? fail(`anchor: no key ${keyId} of ${what} in the run`), input, value);
        if (result === false)
            fail(`anchor: the signature of ${what} (${algorithm}) does not verify over its input as section 7 writes it`);
        if (result === true)
            verified++;
    };

    for (const commit of commits.values()) {
        for (const signature of commit.signatures ?? [])
            check(`the commit ${commit['@id']}`, signature, roleSignatureInput(CONTEXTS.commitSignature, signature, 'commit', commitAsSigned(commit)));
        for (const signature of commit.changeSet?.signatures ?? [])
            check(`the change set of the commit ${commit['@id']}`, signature, changeSetSignatureInput(commit.changeSet, signature));
    }

    for (const { checkpoint } of checkpoints)
        for (const signature of checkpoint.signatures ?? [])
            check(`the checkpoint ${checkpoint['@id']}`, signature, roleSignatureInput(CONTEXTS.checkpointSignature, signature, 'checkpoint', checkpointAsSigned(checkpoint)));

    for (const vector of history.versions) {
        const operator = documentOf(vector).operator;
        for (const signature of operator?.keyStatement?.signatures ?? [])
            check(`the key statement of ${vector.id}`, signature, keyStatementSignatureInput(operator.keyStatement, signature));
        for (const certificate of operator?.signingKeyCertificates ?? [])
            check(`a certificate of ${vector.id}`, certificate, certificateSignatureInput(certificate));
    }

    if (verified < 100)
        fail(`anchor: only ${verified} signatures of the run verified, the inputs of section 7 are not checked`);

    // The attestations the run embeds, in its proofs and the evidence of its driver: as section 7 signs those of a snapshot.
    const attestations = [];
    const embedded = (value) => {
        if (Array.isArray(value))
            value.forEach(embedded);
        else if (value !== null && typeof value === 'object' && value[RAW] === undefined) {
            if (Array.isArray(value.attestations))
                attestations.push(...value.attestations);
            Object.values(value).forEach(embedded);
        }
    };
    documents.forEach(({ json }) => embedded(json));

    const verifiedBefore = verified;
    for (const attestation of attestations)
        check(`an attestation of the commit ${attestation.commitId}`, attestation, attestationSignatureInput(attestation));
    if (verified === verifiedBefore)
        fail('anchor: no attestation of the run verified, the input of an attestation of section 7 is not checked');

    // ES256 with the nonces of RFC 6979: its example of P-256 and SHA-256 (A.2.5), and verified by node:crypto.
    const rfc = es256Of(0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721n);
    anchor('the public key of RFC 6979, A.2.5', Buffer.from(rfc.coseKey, 'base64').subarray(8).toString('hex').replace('225820', ''),
           '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6' + '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299');
    anchor('the ES256 signature of "sample" of RFC 6979, A.2.5', Buffer.from(rfc.sign('sample'), 'base64').toString('hex'),
           'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716' + 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8');
    anchor('the ES256 signature of "test" of RFC 6979, A.2.5', Buffer.from(rfc.sign('test'), 'base64').toString('hex'),
           'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367' + '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083');
    if (verifiesWith('ES256', rfc.coseKey, 'sample', rfc.sign('sample')) !== true)
        fail('anchor: node:crypto does not verify the ES256 signature of RFC 6979, A.2.5');

}


// ---- Applying a change set to the content, as far as the histories below need it (4) -------------------------------
//
// What a change set leads to, so that its afterETags and the ETags of its commit can be calculated: the changes as given,
// lastChange set as section 4 says, of the entity changed and of every entity embedding it, and of the roaming network.
// Nothing is checked here: a change set the implementations refuse is made as whoever made it would make it.

const PARTY_ARRAYS = {
    ChargingStationOperator:           'chargingStationOperators',
    EMobilityProvider:                 'eMobilityProviders',
    GridOperator:                      'gridOperators',
    ParkingOperator:                   'parkingOperators',
    ChargingStationManufacturer:       'chargingStationManufacturers',
    EnergyMeterManufacturer:           'energyMeterManufacturers',
    TransparencySoftwareManufacturer:  'transparencySoftwareManufacturers',
    ConformityAssessmentBody:          'conformityAssessmentBodies',
};

/** Entities of a party without timestamps, by the type of their party and the array of it holding them (4, Timestamps). */
const PARTY_CHILDREN = {
    ChargingStationModel:   [ 'ChargingStationManufacturer', 'chargingStationModels' ],
    EnergyMeterModel:       [ 'EnergyMeterManufacturer',     'energyMeterModels' ],
    ConformityCertificate:  [ 'ConformityAssessmentBody',    'certificates' ],
    TransparencySoftware:   [ 'TransparencySoftwareManufacturer', 'transparencySoftware' ],
    GridConnectionPoint:    [ 'GridOperator',                'gridConnectionPoints' ],
};

/**
 * Entities a party embeds, by their type: the types of the parties embedding them, the array of a party holding them,
 * whether they have timestamps (4, Timestamps: a parking product has none). The groups of e-mobility providers alone: a
 * group of a charging station operator is not made here but an EVSE group.
 */
const EMBEDDED = {
    ChargingTariffOffer:   [ [ 'ChargingStationOperator', 'EMobilityProvider' ], 'chargingTariffOffers',   true ],
    ChargingStationGroup:  [ [ 'EMobilityProvider' ],                            'chargingStationGroups',  true ],
    ChargingPoolGroup:     [ [ 'EMobilityProvider' ],                            'chargingPoolGroups',     true ],
    ParkingGarage:         [ [ 'ParkingOperator' ],                              'parkingGarages',         true ],
    ParkingSpace:          [ [ 'ParkingOperator', 'ChargingStationOperator' ],   'parkingSpaces',          true ],
    ParkingSensor:         [ [ 'ParkingOperator' ],                              'parkingSensors',         true ],
    ParkingSpaceGroup:     [ [ 'ParkingOperator' ],                              'parkingSpaceGroups',     true ],
    ParkingProduct:        [ [ 'ParkingOperator' ],                              'parkingProducts',        false ],
};

/** A copy of JSON as this script holds it, its numbers as written. */
const copyOf = (value) => Array.isArray(value)                              ? value.map(copyOf)
                        : value !== null && typeof value === 'object'       ? (value[RAW] !== undefined ? { [RAW]: value[RAW] } : Object.fromEntries(Object.entries(value).map(([ key, item ]) => [ key, copyOf(item) ])))
                        :                                                     value;

const byId = (array, id) => (array ?? []).find(entity => entity['@id'] === id);

/** Where a change finds its entity: the object holding the array of it, the array, the entity, what embeds it. */
function placeOf(content, change) {

    const { kind, entityType: type, entityId: id, parentEntityType: parentType, parentEntityId: parentId } = change;

    if (type === 'RoamingNetwork')
        return { entity: content, embedding: [], timestamps: true };

    if (type === 'RoamingNetworkOperator')
        return { entity: content.operator, embedding: [], timestamps: true };

    if (PARTY_ARRAYS[type] !== undefined)
        return { holder: content, property: PARTY_ARRAYS[type], entity: byId(content[PARTY_ARRAYS[type]], id), embedding: [], timestamps: true };

    if (PARTY_CHILDREN[type] !== undefined) {
        const [ partyType, property ] = PARTY_CHILDREN[type];
        const party = parentId !== undefined ? byId(content[PARTY_ARRAYS[partyType]], parentId)
                                             : (content[PARTY_ARRAYS[partyType]] ?? []).find(candidate => byId(candidate[property], id) !== undefined);
        return { holder: party, property, entity: byId(party?.[property], id), embedding: [ party ], timestamps: false };
    }

    // An entity a party embeds: of the party an Add names as its parent, else of the one holding it.
    if (EMBEDDED[type] !== undefined) {
        const [ partyTypes, property, timestamps ] = EMBEDDED[type];
        const party = kind === 'Add' ? (partyTypes.includes(parentType) ? byId(content[PARTY_ARRAYS[parentType]], parentId) : undefined)
                                     : partyTypes.flatMap(partyType => content[PARTY_ARRAYS[partyType]] ?? []).find(candidate => byId(candidate[property], id) !== undefined);
        return { holder: party ?? fail(`section 7: no party of the ${type} ${id}`), property, entity: byId(party[property], id), embedding: [ party ], timestamps };
    }

    // A group of an e-mobility provider while one has it, else of the charging station operator its identification names,
    // as the type compares it: DE-XYZ*G names the group DE*XYZ*G (9.3).
    const provider = type === 'EVSEGroup' ? (content.eMobilityProviders ?? []).find(candidate => kind === 'Add' ? parentType === 'EMobilityProvider' && candidate['@id'] === parentId
                                                                                                                 : byId(candidate.EVSEGroups, id) !== undefined)
                                          : undefined;
    if (provider !== undefined)
        return { holder: provider, property: 'EVSEGroups', entity: byId(provider.EVSEGroups, id), embedding: [ provider ], timestamps: true };

    const named    = id.replace(/^([A-Z]{2})-/, '$1*');
    const operator = (content.chargingStationOperators ?? []).filter(candidate => named.startsWith(candidate['@id'] + '*')).sort((left, right) => right['@id'].length - left['@id'].length)[0]
                         ?? fail(`section 7: no charging station operator of the ${type} ${id}`);

    if (type === 'EVSEGroup' || type === 'ChargingPool') {
        const property = type === 'EVSEGroup' ? 'EVSEGroups' : 'chargingPools';
        return { holder: operator, property, entity: byId(operator[property], named), embedding: [ operator ], timestamps: true };
    }

    const pools    = operator.chargingPools ?? [];
    const stations = pools.flatMap(pool => (pool.chargingStations ?? []).map(station => ({ pool, station })));

    if (type === 'ChargingStation') {
        const pool = kind === 'Add' ? byId(pools, parentId) : stations.find(({ station }) => station['@id'] === id)?.pool;
        return { holder: pool, property: 'chargingStations', entity: byId(pool?.chargingStations, id), embedding: [ pool, operator ], timestamps: true };
    }

    if (type === 'EVSE') {
        const { pool, station } = (kind === 'Add' ? stations.find(({ station }) => station['@id'] === parentId) : stations.find(({ station }) => byId(station.EVSEs, id) !== undefined))
                                      ?? fail(`section 7: no charging station of the EVSE ${id}`);
        return { holder: station, property: 'EVSEs', entity: byId(station.EVSEs, id), embedding: [ station, pool, operator ], timestamps: true };
    }

    fail(`section 7: changes of a ${type} are not made here`);

}

/**
 * The content a change set leads to. What it changes and adds is stamped with its createdAt, but no lastChange goes back:
 * a change set created before the lastChange of the roaming network of the version it is applied to - one rebased onto a
 * later head - is stamped with that lastChange (POI3-ISSUES.md S5; WWCP_POI `12e993a`), the created of what it adds
 * without one too.
 */
function applied(before, changes, createdAt) {

    const content = copyOf(before);
    const stamp   = typeof before.lastChange === 'string' && before.lastChange > createdAt ? before.lastChange : createdAt;

    for (const change of changes) {

        const place = placeOf(content, change);

        switch (change.kind) {

            case 'Add': {
                const entity = copyOf(change.newValue);
                if (place.timestamps) {
                    entity.created    ??= stamp;
                    entity.lastChange   = stamp;
                }
                place.holder[place.property] = [ ...(place.holder[place.property] ?? []), entity ].sort((left, right) => left['@id'] < right['@id'] ? -1 : 1);
                break;
            }

            case 'Remove':
                place.holder[place.property] = place.holder[place.property].filter(entity => entity !== place.entity);
                if (place.holder[place.property].length === 0)
                    delete place.holder[place.property];
                break;

            case 'UpdateProperty':
            case 'RemoveProperty':
                if (change.kind === 'UpdateProperty')
                    place.entity[change.propertyName] = copyOf(change.newValue);
                else
                    delete place.entity[change.propertyName];
                if (place.timestamps)
                    place.entity.lastChange = stamp;
                break;

            default:
                fail(`section 7: ${change.kind} is not made here`);

        }

        for (const embedding of place.embedding)
            embedding.lastChange = stamp;

    }

    content.lastChange = stamp;

    return content;

}

/** The effective content of a version is its content only without templates and charging tariffs (8.1). */
function checkEffective(content) {
    const text = canonical(content);
    for (const name of [ '"templateIds"', '"chargingTariffs"', '"chargingTariffIds"', 'Templates"' ])
        if (text.includes(name))
            fail(`section 7: the effective content of a version with ${name} is not calculated here`);
    return content;
}


// ---- A history the generator makes, and the steps taking it -------------------------------------------------------

/**
 * A history of a roaming network from the genesis of its first epoch: its documents by name (JSON text), the steps that
 * take them, its head. `prepare` makes a commit of the head, `take` takes one, `checkpoint` makes the next checkpoint of
 * the head, `nextEpoch` starts the epoch its final checkpoint names.
 */
function generatedHistory(id, description, genesis, leader) {

    const documents  = {};
    const steps      = [];
    const text       = (value) => canonical(value);

    const signedInRole = (context, name, signed, signers, signedAt) =>
        signers.map(({ key, role = 'roamingNetworkOperator', signer = leader.signer }) => {
            const signature = { role, signer, signedAt, algorithm: key.algorithm, keyId: key.id };
            return { ...signature, value: key.sign(roleSignatureInput(context, signature, name, signed)) };
        });

    const signCommit = (commit, signers, signedAt) =>
        ({ ...commit, signatures: signedInRole(CONTEXTS.commitSignature, 'commit', commitAsSigned(commit), signers, signedAt) });

    let epoch      = { number: 1, hash: 'sha256' };
    let head;

    const genesisCommit = (content, more = {}) => {
        const commit = { roamingNetworkId: content['@id'], revision: 0, eTags: eTagsOf(checkEffective(content)), ...more };
        return { '@id': commitIdOf(commit, epoch.hash), ...commit };
    };

    {
        const commit = signCommit(genesisCommit(genesis), [ { key: leader.key } ], genesis.created);
        documents.genesis = text({ commit, roamingNetwork: genesis });
        steps.push({ op: 'fromSnapshot', document: 'genesis' });
        head = { content: genesis, commit, versions: [ { commit, content: genesis } ], checkpoints: [] };
    }

    const history = {

        id, description, documents,

        get head()   { return head; },
        get epoch()  { return epoch; },

        /** The steps so far, and the given ones after them. */
        steps: (...more) => [ ...steps.map(step => ({ ...step })), ...more ],

        /** The step that checks the head as the generator calculated it. */
        expectHead: () => ({ op: 'expectHead', epoch: epoch.number, revision: head.commit.revision, commitId: head.commit['@id'], eTags: head.commit.eTags.map(eTag => etagText(eTag, id)) }),

        /** The content of the version of a revision of the epoch. */
        contentAt: (revision) => (head.versions.find(version => version.commit.revision === revision) ?? fail(`${id}: no version of the revision ${revision}`)).content,

        /**
         * A commit of a change set made for the head, or for the content `before`: its changes, signed by the given keys,
         * leading to what they lead to, or to `content` where given.
         */
        prepare: ({ createdAt, description: what, changes, signers, metadata, content, before = head.content }) => {
            const after      = checkEffective(content ?? applied(before, changes, createdAt));
            const changeSet  = { roamingNetworkId: genesis['@id'], createdAt, description: { en: what }, ...(metadata === undefined ? {} : { metadata }), changes,
                                 beforeETags: eTagsOf(before).slice(0, 2), afterETags: eTagsOf(after).slice(0, 2) };
            const changeSetId = changeSetIdOf(changeSet);
            const signed     = { '@id': changeSetId, ...changeSet };
            const commit     = { roamingNetworkId: genesis['@id'], revision: head.commit.revision + 1, eTags: eTagsOf(after), ...(epoch.number > 1 ? { epoch: epoch.number } : {}),
                                 parentIds: [ head.commit['@id'] ],
                                 changeSet: { ...signed, signatures: signers.map(key => ({ algorithm: key.algorithm, keyId: key.id, value: key.sign(changeSetSignatureInput(signed, { algorithm: key.algorithm, keyId: key.id })) })) } };
            return { commit: signCommit({ '@id': commitIdOf(commit, epoch.hash), ...commit }, [ { key: leader.key } ], createdAt), content: after };
        },

        /** Keeps a document of the history under its name, e.g. a snapshot another server gives of it. */
        keepDocument: (name, document) => {
            const value = text(document);
            if (documents[name] !== undefined && documents[name] !== value)
                fail(`${id}: another document ${name} is there already`);
            documents[name] = value;
            return name;
        },

        /** Keeps a commit or a checkpoint of the history under its name, e.g. one to be refused or the control of one. */
        keep: (name, prepared) => history.keepDocument(name, prepared.commit ?? prepared),

        /** Takes a commit: its step follows, and it is the head. */
        take: (name, prepared) => {
            history.keep(name, prepared);
            steps.push({ op: 'append', document: name });
            head = { content: prepared.content, commit: prepared.commit, versions: [ ...head.versions, prepared ], checkpoints: head.checkpoints };
            return prepared;
        },

        /**
         * The next checkpoint of the head (10.1): its commits those since the commit of the one before, every one of the
         * epoch for the first; the first of a later epoch names the final one of the epoch before (11.3).
         */
        checkpoint: ({ createdAt, signers, final, next, commitId = head.commit['@id'] }) => {
            const latest   = head.checkpoints.at(-1);
            const all      = head.versions.map(version => version.commit);
            const until    = all.findIndex(commit => commit['@id'] === commitId);
            const from     = latest === undefined ? 0 : all.findIndex(commit => commit['@id'] === latest.commitId) + 1;
            const commits  = latest !== undefined && from > until ? [ all[until] ] : all.slice(from, until + 1);
            const commit   = all[until];
            const content  = { roamingNetworkId: genesis['@id'], epoch: epoch.number, sequence: latest === undefined ? 0 : latest.sequence + 1,
                               ...(latest === undefined ? {} : { previousId: latest['@id'] }), commitId, revision: commit.revision, eTags: commit.eTags,
                               commits: { '@merkleRoot': mth(hashOf(epoch.hash), commits.map(commitLeafOf)).toString('hex'), '@size': commits.length },
                               createdAt, ...(final ? { final: true, next } : {}),
                               ...(latest === undefined && epoch.previous !== undefined ? { previous: epoch.previous } : {}) };
            const identified = { '@id': checkpointIdOf(content, epoch.hash), ...content };
            return { ...identified, signatures: signedInRole(CONTEXTS.checkpointSignature, 'checkpoint', checkpointAsSigned(identified), signers, createdAt) };
        },

        /** Takes a checkpoint. */
        takeCheckpoint: (name, checkpoint) => {
            history.keep(name, checkpoint);
            steps.push({ op: 'takeCheckpoint', document: name });
            head = { ...head, checkpoints: [ ...head.checkpoints, checkpoint ] };
            return checkpoint;
        },

        /** Starts the epoch the final checkpoint names (11.3): its genesis has the version of that checkpoint, revision 0. */
        nextEpoch: () => {
            const final = head.checkpoints.at(-1);
            if (final?.final !== true)
                fail(`${id}: no final checkpoint to start the next epoch from`);
            epoch = { number: final.next.epoch, hash: final.next.profiles.identificationHash, profiles: final.next.profiles,
                      previous: { epoch: final.epoch, checkpointId: final['@id'], eTags: final.eTags } };
            const commit = genesisCommit(head.content, { epoch: epoch.number, profiles: epoch.profiles });
            anchor(`${id}: the ETags of the genesis of the epoch ${epoch.number}`, JSON.stringify(commit.eTags), JSON.stringify(final.eTags));
            steps.push({ op: 'startNextEpoch', genesisCommitId: commit['@id'] });
            head = { content: head.content, commit, versions: [ { commit, content: head.content } ], checkpoints: [] };
            return commit;
        },

    };

    return history;

}


// ---- Keys of its own: of seeds of their names (sections 7 and 8) ----------------------------------------------------

/** A seed of a key of its own, of its name: deterministic, and no key of anyone. */
const seedOf = (name, bytes = 32) => createHash('shake256', { outputLength: bytes }).update(`WWCPPOIConformanceTests: ${name}`).digest('hex');

/** A key of POI (4.1): its COSE key, its @id (the RFC 9679 thumbprint), its JSON with what it names, and its signatures. */
const keyOf = (algorithm, seed, more = {}) => {
    const pair = algorithm === 'Ed25519' ? (() => { const ed = ed25519(seed); return { coseKey: coseKeyOf(ed.publicKey), sign: ed.sign }; })()
               : algorithm === 'Ed448'   ? ed448(seed)
               : algorithm === 'ES256'   ? es256(seed)
               :                           fail(`no keys of ${algorithm}`);
    const id   = sha256(Buffer.from(pair.coseKey, 'base64'));
    if (verifiesWith(algorithm, pair.coseKey, id, pair.sign(id)) !== true)
        fail(`anchor: node:crypto does not verify a signature of the ${algorithm} key ${id}`);
    return { algorithm, id, sign: pair.sign, json: { '@id': id, key: pair.coseKey, ...more } };
};


// ---- The histories and what they take and refuse --------------------------------------------------------------------

function signedHistories() {

    const S = (text, what) => quoted(SPEC, text, what);

    const inOrder    = (keys) => [ ...keys ].sort((left, right) => left.id < right.id ? -1 : 1).map(key => key.json);
    const NOT_AFTER   = '2027-10-17T00:00:00.000Z';

    // ---- The roaming network operator DE*RNO: the identity keys of Alpha and Beta of section 6, their signing keys for
    //      the party (that of Alpha the attestation key of section 6), and for certificates and tariffs alone.
    const alphaIdentity      = keyOf('Ed25519', S('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f', 'the seed of the identity key of Alpha'), { holder: 'Alpha' });
    const betaIdentity       = keyOf('Ed25519', S('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'the seed of the identity key of Beta'),  { holder: 'Beta' });
    const rnoSigning         = (name, holder, usages, seed = seedOf(name)) => keyOf('Ed25519', seed, { notAfter: NOT_AFTER, holder, usages });
    const alphaParty         = rnoSigning('Alpha, party',        'Alpha', [ 'party' ], S('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'the seed of the signing key of Alpha'));
    const betaParty          = rnoSigning('Beta, party',         'Beta',  [ 'party' ]);

    anchor('the identity key of Alpha', alphaIdentity.id, S('1ef48003e1c482f88fa9f4ecb3d9cdeeb2037d3be4550ad6ee1854a2c5b0b802', 'its @id'));
    anchor('the signing key of Alpha',  alphaParty.id,    S('ea671729aa29c6140b5129b8d59e13fd9fbd4b96e37b3c5185fb11c3eeeac554', 'its @id'));

    const T0 = '2026-10-18T08:00:00.000Z';

    const certificateOf = (signing, certifier) => {
        const fields = { roamingNetworkOperatorId: 'DE*RNO', signingKey: signing.json, signedAt: T0, algorithm: certifier.algorithm, keyId: certifier.id };
        return { ...fields, value: certifier.sign(certificateSignatureInput(fields)) };
    };

    const rnoOf = (signingKeys) => {
        const statement = { roamingNetworkId: 'rn1', roamingNetworkOperatorId: 'DE*RNO', identityKeys: inOrder([ alphaIdentity, betaIdentity ]), minConsensus: 2,
                            signedAt: T0, validUntil: '2026-11-17T08:00:00.000Z' };
        return {
            '@id':                   'DE*RNO',
            name:                    { en: 'Roaming Network Operator' },
            minConsensus:            2,
            keyStatement:            { ...statement, signatures: [ alphaIdentity, betaIdentity ].map(key => ({ algorithm: key.algorithm, keyId: key.id, value: key.sign(keyStatementSignatureInput(statement, { algorithm: key.algorithm, keyId: key.id })) })) },
            signingKeyCertificates:  signingKeys.map(([ signing, certifier ]) => certificateOf(signing, certifier))
                                                .sort((left, right) => left.signingKey['@id'] < right.signingKey['@id'] ? -1 : left.signingKey['@id'] > right.signingKey['@id'] ? 1 : left.keyId < right.keyId ? -1 : 1),
            identityKeys:            inOrder([ alphaIdentity, betaIdentity ]),
            created:                 T0,
            lastChange:              T0,
        };
    };

    const networkOf = (operator) => ({ '@context': CONTEXT + 'v1', '@id': 'rn1', name: { en: 'Example' }, operator, created: T0, lastChange: T0 });

    const leader = { key: alphaParty, signer: 'DE*RNO' };

    const histories = [];
    const replays   = [];

    /** A replay of a history: its steps, the last one taken or refused; a refused one with its control, taken in its place. */
    const replay = (id, history, expected, description, basis, { steps, control, reason, ...more }) => {
        if (expected === 'refused' && control === undefined)
            fail(`${id}: a refusal without its control`);
        replays.push({ id, description, basis, history: history.id, commitAndCheckpointSignatures: 'unchecked', expected, steps,
                       ...(control === undefined ? {} : { control }), ...(reason === undefined ? {} : { reason }), ...more });
    };

    /** The replays of a history at its head: one taking it, one taking a document after it, one refusing a document after it. */
    const replaysOf = (history) => ({
        accepted:  (id, description, basis, more = {}) =>
                       replay(id, history, 'accepted', description, basis, { steps: history.steps(history.expectHead()), ...more }),
        then:      (id, description, basis, document, prepared, more = {}) =>
                       replay(id, history, 'accepted', description, basis, { steps: history.steps({ op: 'append', document: history.keep(document, prepared) }, expectHeadOf(history, prepared)), ...more }),
        refused:   (id, description, basis, document, prepared, control, { op = 'append', ...more } = {}) =>
                       replay(id, history, 'refused', description, basis, { steps: history.steps({ op, document: history.keep(document, prepared) }), control, ...more }),
    });

    const expectHeadOf = (history, prepared) => ({ op: 'expectHead', epoch: history.epoch.number, revision: prepared.commit.revision, commitId: prepared.commit['@id'],
                                                   eTags: prepared.commit.eTags.map(eTag => etagText(eTag, history.id)) });

    const B = (section) => `${SPEC}, ${section}`;

    // ---- Changes (4), each with the old value it finds where one is given.

    const parentOf  = (parent) => parent === undefined ? {} : { parentEntityType: parent[0], parentEntityId: parent[1] };
    const add       = (entityType, newValue, parent)                                  => ({ kind: 'Add',            entityType, entityId: newValue['@id'], ...parentOf(parent), newValue });
    const update    = (entityType, entityId, propertyName, oldValue, newValue, parent) => ({ kind: 'UpdateProperty', entityType, entityId, ...parentOf(parent), propertyName, ...(oldValue === undefined ? {} : { oldValue }), newValue });
    const unset     = (entityType, entityId, propertyName, oldValue, parent)           => ({ kind: 'RemoveProperty', entityType, entityId, ...parentOf(parent), propertyName, oldValue });
    const remove    = (entityType, entityId, oldValue, parent)                         => ({ kind: 'Remove',         entityType, entityId, ...parentOf(parent), oldValue });

    /** What a change finds in the head of a history: the entity, or its property (JSON null where it is absent). */
    const found = (history, entityType, entityId, propertyName, parent) => {
        const place = placeOf(history.head.content, { kind: 'UpdateProperty', entityType, entityId, ...parentOf(parent) });
        const value = place.entity ?? fail(`${history.id}: no ${entityType} ${entityId} in the head`);
        return copyOf(propertyName === undefined ? value : value[propertyName] ?? null);
    };

    /** An object without its properties given as undefined: what a variant leaves out. */
    const defined = (object) => Object.fromEntries(Object.entries(object).filter(([ , value ]) => value !== undefined));

    const minute = (n) => new Date(Date.parse(T0) + n * 60_000).toISOString();

    const party = (id, name, identity, signing, more = {}) => ({ '@id': id, name, ...more, signingKeys: inOrder(signing), identityKeys: inOrder(identity) });


    // =================================================================================================================
    //  history-parties: the parties of rn1, what they add and who signs it (4, 4.1)
    // =================================================================================================================

    const alphaCertificates  = rnoSigning('Alpha, certificates', 'Alpha', [ 'certificates' ]);
    const betaCertificates   = rnoSigning('Beta, certificates',  'Beta',  [ 'certificates' ]);
    const alphaTariffs       = rnoSigning('Alpha, tariffs',      'Alpha', [ 'tariffs' ]);
    const betaTariffs        = rnoSigning('Beta, tariffs',       'Beta',  [ 'tariffs' ]);

    const parties = generatedHistory('history-parties',
                                     'The roaming network rn1 of DE*RNO, the quorum of Alpha and Beta with signing keys for the party, for certificates and for tariffs alone; the parties it adds, among them a conformity assessment body and a grid operator without keys, and what they add.',
                                     networkOf(rnoOf([ [ alphaParty, alphaIdentity ], [ betaParty, betaIdentity ], [ alphaCertificates, alphaIdentity ], [ betaCertificates, betaIdentity ],
                                                       [ alphaTariffs, alphaIdentity ], [ betaTariffs, betaIdentity ] ])),
                                     leader);
    histories.push(parties);

    const P = replaysOf(parties);

    // The parties, each with its keys: a charging station operator and an e-mobility provider of the same prefix, two
    // charging station manufacturers, an energy meter and a transparency software manufacturer, a conformity assessment
    // body; and a conformity assessment body and a grid operator without keys.
    const gefIdentity        = keyOf('Ed25519', seedOf('DE*GEF, identity'));
    const gefInfrastructure  = keyOf('Ed25519', seedOf('DE*GEF, infrastructure'),    { notAfter: NOT_AFTER, usages: [ 'infrastructure' ] });
    const gefExpiring        = keyOf('Ed25519', seedOf('DE*GEF, expiring'),          { notAfter: minute(7.5), usages: [ 'infrastructure' ] });
    const gefParty           = keyOf('Ed25519', seedOf('DE*GEF, party'),             { notAfter: NOT_AFTER, usages: [ 'party' ] });
    const gefRenewed         = keyOf('Ed25519', seedOf('DE*GEF, infrastructure 2'),  { notAfter: NOT_AFTER, usages: [ 'infrastructure' ] });
    const empIdentity        = keyOf('Ed25519', seedOf('DE-GEF, identity'));
    const empSigning         = keyOf('Ed25519', seedOf('DE-GEF, signing'),           { notAfter: NOT_AFTER });
    const gdIdentity         = keyOf('Ed448',   seedOf('GraphDefined, identity', 57));
    const gdModels           = keyOf('Ed448',   seedOf('GraphDefined, models', 57),  { notAfter: NOT_AFTER, usages: [ 'models' ] });
    const wzIdentity         = keyOf('Ed25519', seedOf('Winzerla, identity'));
    const wzModels           = keyOf('Ed25519', seedOf('Winzerla, models'),          { notAfter: NOT_AFTER, usages: [ 'models' ] });
    const kdmIdentity        = keyOf('Ed25519', seedOf('KERNBERG, identity'));
    const kdmModels          = keyOf('Ed25519', seedOf('KERNBERG, models'),          { notAfter: NOT_AFTER, usages: [ 'models' ] });
    const ptbIdentity        = keyOf('ES256',   seedOf('PTB, identity'));
    const ptbCertificates    = keyOf('ES256',   seedOf('PTB, certificates'),         { notAfter: NOT_AFTER, usages: [ 'certificates' ] });
    const bsiIdentity        = keyOf('Ed25519', seedOf('BSI, identity'));
    const bsiCertificates    = keyOf('Ed25519', seedOf('BSI, certificates'),         { notAfter: NOT_AFTER, usages: [ 'certificates' ] });
    const occIdentity        = keyOf('Ed25519', seedOf('OpenChargingCloud, identity'));
    const occSoftware        = keyOf('Ed25519', seedOf('OpenChargingCloud, software'), { notAfter: NOT_AFTER, usages: [ 'software' ] });

    parties.take('commit-1', parties.prepare({
        createdAt:    minute(1),
        description:  'DE*GEF and DE-GEF, GraphDefined, Winzerla and KERNBERG, OpenChargingCloud, the PTB, and the BSI and DE*NET without keys',
        changes:      [ add('ChargingStationOperator',     party('DE*GEF',       { en: 'GraphDefined Charging Solutions' }, [ gefIdentity ], [ gefInfrastructure, gefExpiring, gefParty ])),
                        add('EMobilityProvider',           party('DE-GEF',       { en: 'GraphDefined Mobility' },           [ empIdentity ], [ empSigning ])),
                        add('ChargingStationManufacturer', party('GraphDefined', { en: 'GraphDefined Charging Stations' },  [ gdIdentity ],  [ gdModels ])),
                        add('ChargingStationManufacturer', party('Winzerla',     { en: 'Winzerla Ladetechnik' },            [ wzIdentity ],  [ wzModels ])),
                        add('EnergyMeterManufacturer',     party('KERNBERG',     { en: 'Kernberg DC Metering' },            [ kdmIdentity ], [ kdmModels ])),
                        add('ConformityAssessmentBody',    party('PTB',          { de: 'Physikalisch-Technische Bundesanstalt' }, [ ptbIdentity ], [ ptbCertificates ], { notifiedFor: [ 'MID' ] })),
                        add('TransparencySoftwareManufacturer', party('OpenChargingCloud', { en: 'Open Charging Cloud' },    [ occIdentity ], [ occSoftware ])),
                        add('ConformityAssessmentBody',    { '@id': 'BSI', name: { de: 'Bundesamt für Sicherheit in der Informationstechnik' }, notifiedFor: [ 'CRA' ] }),
                        add('GridOperator',                { '@id': 'DE*NET', name: { de: 'Netze Jena' } }) ],
        signers:      [ alphaParty, betaParty, gefIdentity, empIdentity, gdIdentity, wzIdentity, kdmIdentity, ptbIdentity, occIdentity ],
    }));

    P.accepted('parties-added', 'The roaming network operator adds ten parties, a conformity assessment body and a grid operator without keys among them, signed by two holders of its quorum and, proving their possession, by each new identity key.', B('4.1'));

    // ---- The models of the manufacturers, each in the hardware revisions and firmware versions it has (csharp-review 16).
    const commit2 = (release = {}) => parties.prepare({
        createdAt:    minute(2),
        description:  'The models of GraphDefined, Winzerla and KERNBERG, and Chargy 1.5.0 of OpenChargingCloud',
        changes:      [ add('ChargingStationModel', { '@id': 'GD-DC300', name: { en: 'GraphDefined DC 300' }, hardwareRevisions: [ '1.0', '1.1' ], firmwareVersions: [ '2.4.0', '2.5.0' ], maxPower: 300000 }, [ 'ChargingStationManufacturer', 'GraphDefined' ]),
                        add('ChargingStationModel', { '@id': 'W-AC11',   name: { en: 'Winzerla AC 11' },      hardwareRevisions: [ 'A' ],          firmwareVersions: [ '1.0' ],            maxPower: 11000 },  [ 'ChargingStationManufacturer', 'Winzerla' ]),
                        add('ChargingStationModel', { '@id': 'W-AC22',   name: { en: 'Winzerla AC 22' },      hardwareRevisions: [ 'A' ],          firmwareVersions: [ '1.0' ],            maxPower: 22000 },  [ 'ChargingStationManufacturer', 'Winzerla' ]),
                        add('EnergyMeterModel',     { '@id': 'KDM-500',  name: { en: 'Kernberg DC meter 500 A' }, hardwareRevisions: [ '2.1' ],   firmwareVersions: [ '3.2', '3.3' ],     maxCurrent: 500 },  [ 'EnergyMeterManufacturer', 'KERNBERG' ]),
                        add('TransparencySoftware', { '@id': 'OpenChargingCloud:chargy-1.5.0', ...release, name: { en: 'Chargy Transparency Software' }, version: '1.5.0',
                                                      openSourceLicenses: [ { '@id': 'AGPL-3.0', description: { en: 'GNU Affero General Public License version 3' }, URLs: [ 'https://www.gnu.org/licenses/agpl-3.0.html' ] } ] },
                                                    [ 'TransparencySoftwareManufacturer', 'OpenChargingCloud' ]) ],
        signers:      [ gdModels, wzModels, kdmModels, occSoftware ],
    });

    // A release is identified under its manufacturer, a certificate under the body issuing it: its owner's identification,
    // a colon and a name of its own without one, the prefix compared without case (POI3-ISSUES.md S36). WWCP_POI3 refuses
    // a change set holding one identified otherwise since `045e180`.
    const S36B     = B('4.1, How releases and certificates are identified');
    const notUnder = (kind, id, owner) => kind === 'release'
                         ? `The transparency software release '${id}' of the manufacturer '${owner}' is not identified as one of it: by '${owner}:' and a name without a colon!`
                         : `The certificate '${id}' of the conformity assessment body '${owner}' is not identified as one of it: by '${owner}:' and a name without a colon!`;
    const commit2Taken = commit2();
    parties.keep('commit-2', commit2Taken);
    P.refused('release-not-under-its-manufacturer', 'OpenChargingCloud adds its release identified without it: chargy-1.5.0.', S36B,
              'commit-2-release-alone', commit2({ '@id': 'chargy-1.5.0' }), 'commit-2',
              { reason: notUnder('release', 'chargy-1.5.0', 'OpenChargingCloud') });
    P.refused('release-under-another-manufacturer', 'OpenChargingCloud adds its release identified under GraphDefined: GraphDefined:chargy-1.5.0, which the meters, stations and certificates of GraphDefined would name.', S36B,
              'commit-2-release-of-another', commit2({ '@id': 'GraphDefined:chargy-1.5.0' }), 'commit-2',
              { reason: notUnder('release', 'GraphDefined:chargy-1.5.0', 'OpenChargingCloud') });
    P.then('release-under-its-manufacturer-in-another-case', 'OpenChargingCloud adds its release identified under it in lowercase, openchargingcloud:chargy-1.5.0: the prefix is compared without case.', S36B,
           'commit-2-release-lowercase', commit2({ '@id': 'openchargingcloud:chargy-1.5.0' }));
    parties.take('commit-2', commit2Taken);

    // ---- Certificates of the PTB: one of a model of charging stations, naming the meter it was issued with, one of a
    //      model of energy meters, each for hardware revisions and firmware versions of its model (csharp-review 16, 17).
    const certificateOfPTB = { '@id': 'PTB:2026-0042', legislation: 'MID', chargingStationManufacturerId: 'GraphDefined', chargingStationModel: 'GD-DC300', hardwareRevisions: [ '1.0' ], firmwareVersions: [ '2.5.0' ],
                               energyMeters: [ { manufacturerId: 'KERNBERG', modelId: 'KDM-500', hardwareRevisions: [ '2.1' ], firmwareVersions: [ '3.2' ] } ],
                               verifiedTransparencySoftwareIds: [ 'OpenChargingCloud:chargy-1.5.0' ], compatibleTransparencySoftwareIds: [], notBefore: minute(3), notAfter: '2036-10-18T08:03:00.000Z' };
    const meterCertificate = { '@id': 'PTB:2026-0017', legislation: 'MID', energyMeterManufacturerId: 'KERNBERG', energyMeterModel: 'KDM-500', hardwareRevisions: [ '2.1' ], firmwareVersions: [ '3.2' ],
                               verifiedTransparencySoftwareIds: [ 'OpenChargingCloud:chargy-1.5.0' ], compatibleTransparencySoftwareIds: [], notBefore: minute(3), notAfter: '2036-10-18T08:03:00.000Z' };

    parties.take('commit-3', parties.prepare({
        createdAt:    minute(3),
        description:  'PTB:2026-0042 for the GD-DC300 with the KDM-500, PTB:2026-0017 for the KDM-500',
        changes:      [ add('ConformityCertificate', certificateOfPTB, [ 'ConformityAssessmentBody', 'PTB' ]), add('ConformityCertificate', meterCertificate, [ 'ConformityAssessmentBody', 'PTB' ]) ],
        signers:      [ ptbCertificates ],
    }));

    P.accepted('parties-models-and-certificates', 'The manufacturers add their models in the hardware revisions and firmware versions they have, the PTB a certificate of a model of charging stations naming the meter it was issued with, and one of a model of energy meters.', `${B('4.1')}; csharp-review 16, 17`);

    // ---- A charging pool of DE*GEF: a station of the GD-DC300 naming its certificate, its meter its own; a station of
    //      Winzerla; an EVSE group.
    const meter   = (more = {}) => defined({ '@id': 'DE*GEF*M1*1', manufacturerId: 'KERNBERG', modelId: 'KDM-500', hardwareRevision: '2.1', firmwareVersion: '3.2', certificateIds: [ 'PTB:2026-0017' ], created: minute(4), lastChange: minute(4), ...more });
    const station = (more = {}, meterMore = {}) => defined({ '@id': 'DE*GEF*S1', manufacturerId: 'GraphDefined', modelId: 'GD-DC300', hardwareRevision: '1.0', firmwareVersion: '2.5.0', certificateIds: [ 'PTB:2026-0042' ],
                                                             EVSEs: [ { '@id': 'DE*GEF*E1*1', maxPower: 150000, energyMeter: meter(meterMore), created: minute(4), lastChange: minute(4) } ], created: minute(4), lastChange: minute(4), ...more });
    const winzerla = { '@id': 'DE*GEF*S2', manufacturerId: 'Winzerla', modelId: 'W-AC22', hardwareRevision: 'A', firmwareVersion: '1.0',
                       EVSEs: [ { '@id': 'DE*GEF*E2*1', maxPower: 22000, created: minute(4), lastChange: minute(4) } ], created: minute(4), lastChange: minute(4) };
    const pool    = (stationMore, meterMore) => ({ '@id': 'DE*GEF*P1', name: { en: 'Jena Paradies' }, chargingStations: [ station(stationMore, meterMore), winzerla ] });
    const poolOf  = (name, stationMore, meterMore) => parties.prepare({
        createdAt:    minute(4),
        description:  name,
        changes:      [ add('ChargingPool', pool(stationMore, meterMore)), add('EVSEGroup', { '@id': 'DE*GEF*EG_HW', name: { en: 'Highway' }, EVSEIds: [ 'DE*GEF*E1*1' ] }) ],
        signers:      [ gefInfrastructure ],
    });

    const commit4 = poolOf('Jena Paradies, a station of the GD-DC300 and one of Winzerla; the EVSE group Highway');
    parties.keep('commit-4', commit4);

    // What the version names, it holds (4.1): models, hardware revisions and firmware versions of the models, certificates
    // of their kind and model. WWCP_POI.TS checks the references a version holds since `813e1d7`; it left them to WWCP_POI
    // before.
    P.refused('station-firmware-of-no-model', 'A charging station naming a firmware version its model does not have.', `${B('4.1')}; csharp-review 16`,
              'commit-4-firmware', poolOf('A station of the GD-DC300 in the firmware 2.6.0', { firmwareVersion: '2.6.0' }), 'commit-4',
              { reason: "is no firmware version of its model 'GD-DC300'" });
    P.refused('station-revision-not-certified', 'A charging station of a hardware revision of its model the certificate it names does not cover.', `${B('4.1')}; csharp-review 16`,
              'commit-4-revision', poolOf('A station of the GD-DC300 in the hardware revision 1.1', { hardwareRevision: '1.1' }), 'commit-4',
              { reason: "does not cover its hardware revision '1.1'" });
    P.refused('station-certificate-of-a-meter', 'A charging station naming the certificate of a model of energy meters.', `${B('4.1')}; csharp-review 17`,
              'commit-4-station-certificate', poolOf('A station naming PTB:2026-0017', { certificateIds: [ 'PTB:2026-0017' ] }), 'commit-4',
              { reason: 'not for a model of charging stations' });
    P.refused('meter-certificate-of-a-station', 'An energy meter naming the certificate of a model of charging stations.', `${B('4.1')}; csharp-review 17`,
              'commit-4-meter-certificate', poolOf('A meter naming PTB:2026-0042', {}, { certificateIds: [ 'PTB:2026-0042' ] }), 'commit-4',
              { reason: 'not for a model of energy meters' });
    P.refused('meter-not-of-the-certificate', 'An energy meter in a firmware version of its model, in a charging station whose certificate names its meters in another one.', `${B('4.1')}; csharp-review 17`,
              'commit-4-meter-firmware', poolOf('A meter in the firmware 3.3', {}, { firmwareVersion: '3.3', certificateIds: undefined }), 'commit-4-meter-firmware-control',
              { reason: "is none of the energy meters the certificate 'PTB:2026-0042' was issued with" });
    parties.keep('commit-4-meter-firmware-control', poolOf('A meter in the firmware 3.2, naming no certificate', {}, { certificateIds: undefined }));

    parties.take('commit-4', commit4);
    P.accepted('parties-station-and-meter', 'A charging station names its model, hardware revision, firmware version and certificate, its energy meter those of its own.', `${B('4.1')}; csharp-review 16, 17`);

    // ---- The roaming network operator states a certificate in place of a body without signing keys (csharp-review 13, 15).
    const certificateOfBSI = (more = {}) => defined({ '@id': 'BSI:2026-0001', chargingStationManufacturerId: 'GraphDefined', chargingStationModel: 'GD-DC300', hardwareRevisions: [ '1.0' ], firmwareVersions: [ '2.5.0' ],
                                                      verifiedTransparencySoftwareIds: [ 'OpenChargingCloud:chargy-1.5.0' ], compatibleTransparencySoftwareIds: [], notBefore: minute(5), notAfter: '2031-10-18T08:05:00.000Z',
                                                      statedBy: 'roamingNetworkOperator', ...more });
    const certificateBy = (signers, more) => parties.prepare({
        createdAt:    minute(5),
        description:  'BSI:2026-0001, stated by the roaming network operator in place of the BSI',
        changes:      [ add('ConformityCertificate', certificateOfBSI(more), [ 'ConformityAssessmentBody', 'BSI' ]) ],
        signers,
    });

    const commit5 = certificateBy([ alphaParty, betaParty ]);
    parties.keep('commit-5', commit5);

    P.then('certificates-of-two-bodies-numbered-alike', 'The roaming network operator adds the certificate BSI:2026-0042 of the BSI in its place, numbered as PTB:2026-0042 of the PTB: two bodies numbering their certificates alike both have them.', S36B,
           'commit-5-numbered-alike', certificateBy([ alphaParty, betaParty ], { '@id': 'BSI:2026-0042' }));
    P.then('rno-states-certificate-with-keys-for-certificates', 'The roaming network operator adds a certificate of a body without signing keys in its place, signed by two holders with signing keys certified for certificates alone.', `${B('4.1')}; csharp-review 13`,
           'commit-5-certificates', certificateBy([ alphaCertificates, betaCertificates ]));
    P.refused('rno-states-certificate-with-keys-for-tariffs', 'The roaming network operator adds a certificate of a body without signing keys in its place, signed by two holders with signing keys certified for tariffs alone: a key of the roaming network operator signs in place of a party what it may sign, or the party.', `${B('4.1')}; csharp-review 13`,
              'commit-5-tariffs', certificateBy([ alphaTariffs, betaTariffs ]), 'commit-5', { reason: "Change 0: Add of the ConformityCertificate 'BSI:2026-0001' needs" });
    P.refused('rno-states-certificate-one-holder', 'The roaming network operator adds a certificate of a body without signing keys in its place, signed by one holder of its quorum of two.', `${B('4.1')}; csharp-review 13`,
              'commit-5-one-holder', certificateBy([ alphaParty ]), 'commit-5', { reason: "Change 0: Add of the ConformityCertificate 'BSI:2026-0001' needs" });
    P.refused('rno-states-certificate-unsaid', 'The roaming network operator adds a certificate of a body without signing keys in its place, without saying so in its statedBy.', `${B('4.1, Who states a certificate')}; csharp-review 15`,
              'commit-5-unsaid', certificateBy([ alphaParty, betaParty ], { statedBy: undefined }), 'commit-5',
              { reason: "The certificate 'BSI:2026-0001' of the conformity assessment body 'BSI' without signing keys is stated by the roaming network operator in its place: its statedBy is 'roamingNetworkOperator'!" });

    parties.take('commit-5', commit5);
    P.accepted('rno-states-certificate', 'The roaming network operator adds a certificate of a body without signing keys in its place, signed by two holders with signing keys for the party, and says so in its statedBy.', `${B('4.1')}; csharp-review 13, 15`);

    {
        const byPTB = (more) => parties.prepare({ createdAt: minute(5.5), description: 'PTB:2026-0099', signers: [ ptbCertificates ],
                                                  changes: [ add('ConformityCertificate', { ...meterCertificate, '@id': 'PTB:2026-0099', ...more }, [ 'ConformityAssessmentBody', 'PTB' ]) ] });
        parties.keep('commit-6-ptb', byPTB({}));
        P.refused('body-certificate-said-by-rno', 'A body with signing keys adds a certificate whose statedBy names the roaming network operator.', `${B('4.1, Who states a certificate')}; csharp-review 15`,
                  'commit-6-ptb-stated', byPTB({ statedBy: 'roamingNetworkOperator' }), 'commit-6-ptb',
                  { reason: "The certificate 'PTB:2026-0099' of the conformity assessment body 'PTB' is stated by the body itself, with its keys: it names no statedBy!" });
        P.refused('certificate-not-under-its-body', 'The PTB adds a certificate identified without it: 2026-0099, its number.', S36B,
                  'commit-6-ptb-number-alone', byPTB({ '@id': '2026-0099' }), 'commit-6-ptb',
                  { reason: notUnder('certificate', '2026-0099', 'PTB') });
        P.refused('certificate-under-another-body', 'The PTB adds a certificate identified under the BSI: BSI:2026-0099.', S36B,
                  'commit-6-ptb-of-another', byPTB({ '@id': 'BSI:2026-0099' }), 'commit-6-ptb',
                  { reason: notUnder('certificate', 'BSI:2026-0099', 'PTB') });
        P.refused('certificate-name-with-a-colon', 'The PTB adds a certificate whose name has a colon: PTB:2026:0099.', S36B,
                  'commit-6-ptb-two-colons', byPTB({ '@id': 'PTB:2026:0099' }), 'commit-6-ptb',
                  { reason: notUnder('certificate', 'PTB:2026:0099', 'PTB') });
        P.then('certificate-under-its-body-in-another-case', 'The PTB adds a certificate identified under it in lowercase, ptb:2026-0099: the prefix is compared without case.', S36B,
               'commit-6-ptb-lowercase', byPTB({ '@id': 'ptb:2026-0099' }));
    }

    // ---- The BSI gets keys, by the roaming network operator recovering them; a certificate the roaming network operator
    //      stated it changes only by stating it itself, removing its statedBy (csharp-review 15).
    parties.take('commit-6', parties.prepare({
        createdAt:    minute(6),
        description:  'The keys of the BSI',
        changes:      [ update('ConformityAssessmentBody', 'BSI', 'signingKeys',  null, inOrder([ bsiCertificates ])),
                        update('ConformityAssessmentBody', 'BSI', 'identityKeys', null, inOrder([ bsiIdentity ])) ],
        signers:      [ alphaIdentity, betaIdentity, bsiIdentity ],
    }));

    const byBSI = (changes, description) => parties.prepare({ createdAt: minute(7), description, changes, signers: [ bsiCertificates ] });
    const commit7 = byBSI([ unset('ConformityCertificate', 'BSI:2026-0001', 'statedBy', 'roamingNetworkOperator', [ 'ConformityAssessmentBody', 'BSI' ]) ], 'The BSI states BSI:2026-0001 itself');
    parties.keep('commit-7', commit7);

    P.refused('body-changes-certificate-said-by-rno', 'A body that got its signing keys since changes a certificate the roaming network operator stated in its place, its statedBy kept.', `${B('4.1, Who states a certificate')}; csharp-review 15`,
              'commit-7-kept', byBSI([ update('ConformityCertificate', 'BSI:2026-0001', 'notAfter', '2031-10-18T08:05:00.000Z', '2030-10-18T08:05:00.000Z', [ 'ConformityAssessmentBody', 'BSI' ]) ], 'The BSI shortens BSI:2026-0001'), 'commit-7',
              { reason: "The certificate 'BSI:2026-0001' of the conformity assessment body 'BSI' is stated by the body itself, with its keys: it names no statedBy!" });

    parties.take('commit-7', commit7);
    P.accepted('body-states-certificate-itself', 'A body that got its signing keys since states a certificate the roaming network operator stated in its place itself, removing its statedBy.', `${B('4.1, Who states a certificate')}; csharp-review 15`);

    // ---- An EVSE changes: the lastChange of everything embedding it changes with it (csharp-review 8); its old value is
    //      compared as canonical JSON (csharp-review 12).
    const maxPowerOf = ({ signer = gefInfrastructure, ...more } = {}) => parties.prepare({
        createdAt:    minute(8),
        description:  'DE*GEF*E1*1 at 300 kW',
        changes:      [ update('EVSE', 'DE*GEF*E1*1', 'maxPower', 'oldValue' in more ? more.oldValue : 150000, 300000) ],
        signers:      [ signer ],
        ...without(more, 'oldValue'),
    });

    const commit8 = maxPowerOf();
    parties.keep('commit-8', commit8);

    {
        // As section 4 said before WWCP_POI 8e6a1fa: the lastChange of the EVSE and of the roaming network alone.
        const content = copyOf(commit8.content);
        const gef     = byId(content.chargingStationOperators, 'DE*GEF');
        const before  = byId(parties.head.content.chargingStationOperators, 'DE*GEF');
        gef.lastChange = before.lastChange;
        gef.chargingPools[0].lastChange = before.chargingPools[0].lastChange;
        gef.chargingPools[0].chargingStations[0].lastChange = before.chargingPools[0].chargingStations[0].lastChange;
        P.refused('lastChange-of-what-embeds-it', 'An EVSE changes, the change set leading to a version in which neither its charging station nor its charging pool nor its operator changed their lastChange, as section 4 said before WWCP_POI 8e6a1fa.', `${B('4, Timestamps')}; csharp-review 8`,
                  'commit-8-lastChange', maxPowerOf({ content }), 'commit-8', { reason: 'The result does not match the change set' });
    }

    P.refused('old-value-other', 'A change whose old value is not the value it finds.', `${B('4, Old values')}; csharp-review 12`,
              'commit-8-old-value', maxPowerOf({ oldValue: 22000 }), 'commit-8', { reason: "Change 0: the property 'maxPower' of the EVSE 'DE*GEF*E1*1' is no longer the expected old value" });
    P.refused('old-value-decimal', 'A change whose old value is 150000.0 where it finds 150000: compared as canonical JSON, they are other values.', `${B('4, Old values')}; csharp-review 12`,
              'commit-8-old-value-decimal', maxPowerOf({ oldValue: { [RAW]: '150000.0' } }), 'commit-8', { reason: "Change 0: the property 'maxPower' of the EVSE 'DE*GEF*E1*1' is no longer the expected old value" });
    P.then('old-value-none', 'A change without old value, its change set not rebased: it compares nothing, the beforeETags pin the version.', `${B('4, Old values')}; csharp-review 12`,
           'commit-8-without-old-value', maxPowerOf({ oldValue: undefined }));
    P.refused('key-expired', 'A change signed by a signing key of its owner that expired before the createdAt of its change set.', `${B('4.1')}; csharp-review 3`,
              'commit-8-expired', maxPowerOf({ signer: gefExpiring }), 'commit-8',
              { reason: `Signature 0: the key '${gefExpiring.id}' of the ChargingStationOperator 'DE*GEF' is not valid at ${minute(8)}!` });
    P.refused('key-expired-besides', 'A change signed by a signing key of its owner and, besides, by one of its owner that expired before the createdAt of its change set: every signature is by a key valid at its createdAt.',
              `${B('4.1; 4.2')} (proposed for every change set, as 4.2 says of one waiting); csharp-review 3`,
              'commit-8-expired-besides', maxPowerOf({ signers: [ gefInfrastructure, gefExpiring ] }), 'commit-8',
              { reason: `Signature 1: the key '${gefExpiring.id}' of the ChargingStationOperator 'DE*GEF' is not valid at ${minute(8)}!` });
    P.then('signature-of-another-party', 'A change signed by a signing key of its owner and, besides, by a signing key of another party: every signature is by a key of a party.', B('4.1'),
           'commit-8-another-party', maxPowerOf({ signers: [ gefInfrastructure, kdmModels ] }));

    // Rebased (4): prepared for the version before the BSI stated its certificate itself, and made again for the head,
    // naming the change set it was prepared from; only its old values tell what a change set committed meanwhile changed.
    // Created at 6.5, before the head of 7, it is stamped 7 (4, Timestamps; POI3-ISSUES.md S5, WWCP_POI `12e993a`).
    {
        const rebased = (what, changes) => {
            const original = parties.prepare({ createdAt: minute(6.5), description: what, changes, signers: [], before: parties.contentAt(6) }).commit.changeSet;
            const entry    = { '@id': original['@id'], beforeETags: original.beforeETags, afterETags: original.afterETags };
            const again    = parties.prepare({ createdAt: minute(6.5), description: what, changes, signers: [ gefInfrastructure ], metadata: { rebasedFrom: [ entry ] } });
            anchor(`the rebasedFrom of '${what}'`, changeSetIdOf({ ...without(again.commit.changeSet, 'metadata'), beforeETags: entry.beforeETags, afterETags: entry.afterETags }), entry['@id']);
            return again;
        };
        const evse = { '@id': 'DE*GEF*E1*2', maxPower: 150000, created: minute(6.5), lastChange: minute(6.5) };
        P.then('rebased-with-old-values', 'A change set prepared for the version before, made again for the head and naming the one it was prepared from: its change gives the old value it finds. Created before the lastChange of the head, it is stamped with that one: no lastChange goes back (S5).', `${B('4, Rebased; Timestamps')}; csharp-review 12`,
               'commit-8-rebased', rebased('DE*GEF*E1*1 at 300 kW, rebased', [ update('EVSE', 'DE*GEF*E1*1', 'maxPower', 150000, 300000) ]));
        P.refused('rebased-without-old-value', 'A change set prepared for the version before, made again for the head and naming the one it was prepared from: its change gives no old value, so a change committed meanwhile may have been overwritten. Created before the lastChange of the head, it is stamped with that one: no lastChange goes back (S5).', `${B('4, Rebased; Timestamps')}; csharp-review 12`,
                  'commit-8-rebased-without-old-value', rebased('DE*GEF*E1*1 at 300 kW, rebased without its old value', [ update('EVSE', 'DE*GEF*E1*1', 'maxPower', undefined, 300000) ]), 'commit-8-rebased',
                  { reason: 'which was rebased, has no old value' });
        P.then('rebased-add', 'A change set prepared for the version before, made again for the head and naming the one it was prepared from: an Add gives no old value. Created before the lastChange of the head, it is stamped with that one: no lastChange goes back (S5).', `${B('4, Rebased; Timestamps')}; csharp-review 12`,
               'commit-8-rebased-add', rebased('DE*GEF*E1*2, rebased', [ add('EVSE', evse, [ 'ChargingStation', 'DE*GEF*S1' ]) ]));
    }

    parties.take('commit-8', commit8);
    P.accepted('lastChange-and-old-value', 'An EVSE changes, with its old value: its charging station, its charging pool and its operator change their lastChange with it.', `${B('4, Timestamps')}; csharp-review 8, 12`);

    // ---- What another party names is not withdrawn while it names it, also not by the roaming network operator; both
    //      change it in one change set both sign (csharp-review 18).
    const leaving = (description, changes, signers) => parties.prepare({ createdAt: minute(9), description, changes, signers });
    const station2Removed     = remove('ChargingStation', 'DE*GEF*S2', found(parties, 'ChargingStation', 'DE*GEF*S2'));
    const winzerlaRemoved     = remove('ChargingStationManufacturer', 'Winzerla', found(parties, 'ChargingStationManufacturer', 'Winzerla'));
    const modelRemoved        = (model) => remove('ChargingStationModel', model, found(parties, 'ChargingStationModel', model, undefined, [ 'ChargingStationManufacturer', 'Winzerla' ]), [ 'ChargingStationManufacturer', 'Winzerla' ]);

    const commit9 = leaving('Winzerla leaves, with the station of DE*GEF of its model', [ station2Removed, winzerlaRemoved ], [ alphaParty, betaParty, gefInfrastructure ]);
    parties.keep('commit-9', commit9);
    parties.keep('commit-9-model-control', leaving('Winzerla withdraws the W-AC11', [ modelRemoved('W-AC11') ], [ wzModels ]));

    P.refused('withdrawn-while-named-party', 'The roaming network operator removes a charging station manufacturer whose model a charging station of another party names.', `${B('4.1, What another party names')}; csharp-review 18`,
              'commit-9-named', leaving('Winzerla leaves', [ winzerlaRemoved ], [ alphaParty, betaParty ]), 'commit-9',
              { reason: "The manufacturer 'Winzerla' of the charging station 'DE*GEF*S2' is unknown in the roaming network: the change set withdraws it while it is still named" });
    P.refused('withdrawn-while-named-model', 'A charging station manufacturer withdraws a model a charging station of another party names.', `${B('4.1, What another party names')}; csharp-review 18`,
              'commit-9-model', leaving('Winzerla withdraws the W-AC22', [ modelRemoved('W-AC22') ], [ wzModels ]), 'commit-9-model-control',
              { reason: "The model 'W-AC22' of the charging station 'DE*GEF*S2' is unknown at its manufacturer 'Winzerla': the change set withdraws it while it is still named" });

    parties.take('commit-9', commit9);
    P.accepted('withdrawn-with-what-names-it', 'The roaming network operator removes a charging station manufacturer together with the charging station of another party naming its model, in one change set both sign.', `${B('4.1, What another party names')}; csharp-review 18`);

    // ---- DE*GEF renews its signing key for infrastructure: the key removed signs nothing more (csharp-review 3, in a
    //      linear history; the merges of section 5.3 the TypeScript port does not take). Keys are given in their order (10).
    const renewing = (keys) => parties.prepare({ createdAt: minute(10), description: 'DE*GEF renews its signing key for infrastructure', signers: [ gefParty ],
                                                 changes: [ update('ChargingStationOperator', 'DE*GEF', 'signingKeys', found(parties, 'ChargingStationOperator', 'DE*GEF', 'signingKeys'), keys) ] });
    const commit10 = renewing(inOrder([ gefRenewed, gefParty ]));
    parties.keep('commit-10', commit10);

    P.refused('new-value-keys-out-of-order', 'A change of the signing keys of a party giving them out of the order of their @ids, in which the content holds them.', `${B('2, Written forms; 4, New values')}; csharp-review 10`,
              'commit-10-out-of-order', renewing(inOrder([ gefRenewed, gefParty ]).reverse()), 'commit-10', { reason: 'is not given as the content holds it' });

    parties.take('commit-10', commit10);

    const evseChange = (signer, maxPower = 250000) => parties.prepare({ createdAt: minute(11), description: `DE*GEF*E1*1 at ${maxPower / 1000} kW`, signers: [ signer ],
                                                                        changes: [ update('EVSE', 'DE*GEF*E1*1', 'maxPower', 300000, maxPower) ] });
    parties.keep('commit-11-renewed', evseChange(gefRenewed));
    P.refused('key-removed', 'A change signed by the signing key its owner removed in the version before.', `${B('4.1')}; csharp-review 3`,
              'commit-11-removed', evseChange(gefInfrastructure), 'commit-11-renewed', { reason: 'is no key of a party of' });

    // ---- What a model rates limits what names it (4.1): no EVSE above the maxPower of the model of its charging station,
    //      no model lowered below one naming it, no energy meter signing with a method its model does not name.
    P.refused('evse-above-its-model', 'An EVSE raised above the maxPower of the model of its charging station.', `${B('4.1, What a model rates')}; csharp-review 19`,
              'commit-11-above-model', evseChange(gefRenewed, 350000), 'commit-11-renewed',
              { reason: "The maximum power of the EVSE 'DE*GEF*E1*1', 350 kW, is above the one of the model 'GD-DC300' of 'GraphDefined' of its charging station 'DE*GEF*S1', 300 kW!" });

    const modelRated = (maxPower) => parties.prepare({ createdAt: minute(11), description: `The GD-DC300 at ${maxPower / 1000} kW`, signers: [ gdModels ],
                                                       changes: [ update('ChargingStationModel', 'GD-DC300', 'maxPower', 300000, maxPower, [ 'ChargingStationManufacturer', 'GraphDefined' ]) ] });
    parties.keep('commit-11-model', modelRated(350000));
    P.refused('model-below-what-names-it', 'A charging station manufacturer lowering the maxPower of its model below an EVSE of a charging station of another party naming it.', `${B('4.1, What a model rates')}; csharp-review 19`,
              'commit-11-model-lowered', modelRated(250000), 'commit-11-model',
              { reason: "The maximum power of the EVSE 'DE*GEF*E1*1', 300 kW, is above the one of the model 'GD-DC300' of 'GraphDefined' of its charging station 'DE*GEF*S1', 250 kW!" });

    const meterSigning = (signatureMethod) => parties.prepare({
        createdAt:    minute(11),
        description:  `The KDM-500 signs with OCMF; DE*GEF*E1*2 with a meter signing with ${signatureMethod}`,
        changes:      [ update('EnergyMeterModel', 'KDM-500', 'signatureMethods', null, [ 'OCMF' ], [ 'EnergyMeterManufacturer', 'KERNBERG' ]),
                        add('EVSE', { '@id': 'DE*GEF*E1*2', maxPower: 150000, energyMeter: meter({ '@id': 'DE*GEF*M1*2', signatureMethods: [ signatureMethod ], created: minute(11), lastChange: minute(11) }) },
                            [ 'ChargingStation', 'DE*GEF*S1' ]) ],
        signers:      [ kdmModels, gefRenewed ],
    });
    parties.keep('commit-11-meter', meterSigning('OCMF'));
    P.refused('meter-signing-not-as-its-model', 'An energy meter signing with a signature method its model does not name, the model naming one.', `${B('4.1, What a model rates')}; csharp-review 19`,
              'commit-11-meter-method', meterSigning('EDL40'), 'commit-11-meter',
              { reason: "The energy meter 'DE*GEF*M1*2' signs with 'EDL40', no signature method of its model 'KDM-500' of 'KERNBERG'!" });

    // ---- What a change set gives is what the content holds (csharp-review 10): an EVSE added with a JSON-LD context, or
    //      with a timestamp not to the millisecond, is refused.
    const evseAdded = (description, evse) => parties.prepare({ createdAt: minute(11), description, signers: [ gefRenewed ],
                                                               changes: [ add('EVSE', { '@id': 'DE*GEF*E1*2', maxPower: 150000, ...evse }, [ 'ChargingStation', 'DE*GEF*S1' ]) ] });
    parties.keep('commit-11-evse', evseAdded('DE*GEF*E1*2', {}));
    parties.keep('commit-11-evse-created', evseAdded('DE*GEF*E1*2, created before', { created: '2026-10-18T08:10:30.000Z' }));

    P.refused('new-value-context', 'An EVSE added naming a JSON-LD context: embedded, an object names none.', `${B('1.1; 4, New values')}; csharp-review 10`,
              'commit-11-evse-context', evseAdded('DE*GEF*E1*2, with its context', { '@context': CONTEXT + 'evse/v1' }), 'commit-11-evse', { reason: 'is not given as the content holds it' });
    P.refused('new-value-timestamp', 'An EVSE added with a timestamp not to the millisecond: the content holds it as yyyy-MM-ddTHH:mm:ss.fffZ.', `${B('2, Written forms; 4, New values')}; csharp-review 10`,
              'commit-11-evse-timestamp', evseAdded('DE*GEF*E1*2, created before', { created: '2026-10-18T08:10:30Z' }), 'commit-11-evse-created', { reason: 'is not given as the content holds it' });

    // ---- A change of a group is one of a provider's group while a provider has it, else one of the group of the operator its
    //      identification names (csharp-review 9): DE-GEF adds a group of the identification of one of DE*GEF, written as
    //      the content holds it, DE*GEF*EG_HW, renames it and removes it again; renamed after it removed it, the change is
    //      one of the operator's group, which the provider does not own. WWCP_POI.TS applies a change of a provider's group
    //      since `1946013`, none before.
    const providerGroup = (description, ...changes) => parties.prepare({ createdAt: minute(12), description, changes, signers: [ empSigning ] });
    const groupAdded    = add('EVSEGroup', { '@id': 'DE*GEF*EG_HW', name: { en: 'Highway' }, EVSEIds: [ 'DE*GEF*E1*1' ] }, [ 'EMobilityProvider', 'DE-GEF' ]);
    const groupRenamed  = update('EVSEGroup', 'DE*GEF*EG_HW', 'name', { en: 'Highway' }, { en: 'Autobahn' });
    const groupRemoved  = (name) => remove('EVSEGroup', 'DE*GEF*EG_HW', { ...groupAdded.newValue, name, created: minute(12), lastChange: minute(12) });

    parties.keep('commit-12-provider', providerGroup('DE-GEF adds an EVSE group Highway, names it Autobahn and removes it', groupAdded, groupRenamed, groupRemoved({ en: 'Autobahn' })));
    P.refused('owner-of-what-was-removed', 'An e-mobility provider adds an EVSE group of the identification of one of the charging station operator of its prefix, removes it and then renames it, in one change set it alone signs: once its group is removed, the change is one of the group of the operator, which the provider does not own.', `${B('4.1, Within a change set; 9.3')}; csharp-review 9`,
              'commit-12-provider-removed', providerGroup('DE-GEF adds an EVSE group Highway, removes it and names it Autobahn', groupAdded, groupRemoved({ en: 'Highway' }), groupRenamed),
              'commit-12-provider', { reason: "needs a signature by a signing key of the ChargingStationOperator 'DE*GEF'" });

    // ---- The roaming network operator adds a grid connection point in place of a grid operator without keys
    //      (csharp-review 13). WWCP_POI.TS applies a change of a grid connection point since `1946013`, none before.
    const connection = (signers) => parties.prepare({ createdAt: minute(12), description: 'connection-1 of DE*NET, by the roaming network operator in its place', signers,
                                                      changes: [ add('GridConnectionPoint', { '@id': 'connection-1' }, [ 'GridOperator', 'DE*NET' ]) ] });
    P.then('rno-adds-grid-connection-point', 'The roaming network operator adds a grid connection point of a grid operator without keys in its place, signed by two holders with signing keys for the party.', `${B('4.1')}; csharp-review 13`,
           'commit-12-connection', connection([ alphaParty, betaParty ]));
    P.refused('rno-adds-grid-connection-point-with-keys-for-tariffs', 'The roaming network operator adds a grid connection point of a grid operator without keys in its place, signed by two holders with signing keys for tariffs alone.', `${B('4.1')}; csharp-review 13`,
              'commit-12-connection-tariffs', connection([ alphaTariffs, betaTariffs ]), 'commit-12-connection',
              { reason: "Change 0: Add of the GridConnectionPoint 'connection-1' needs" });

    // ---- EV Taler (concepts/EVTaler.md, phase 1): DE*GEF adds a signing key for payments; its merchant, the evTaler of
    //      the example of ChargingStationOperator.md, is signed by a key that may sign payments, not by one for the party,
    //      nor by the roaming network operator, which signs in place of a party without signing keys only (SignerOf of
    //      WWCP_POI3), not of DE*GEF; a charging pool naming the payment option EVTaler
    //      needs it, checked after the last change of a change set, so that one change set adds both in either order and
    //      removes the merchant only with the last pool naming EVTaler.
    const EV_TALER_BASIS = `${B('4.1')}; ${EV_TALER_DOC}`;
    S('a change of the `evTaler` of a charging station operator, an element change within it as well, the usage\n`payments`.', 'that a change of the merchant is signed for payments');
    S('so the RNO\nsigns in place of a party without signing keys', 'that the roaming network operator signs in place of a party without signing keys');
    quoted(EV_TALER_DOC, 'checked\n  when the operator is made and after the last change of a change set, so that one change set may add both in either\n  order, and remove `evTaler` only with the last `EVTaler`.',
           'when a pool naming EVTaler is checked for the merchant');

    const merchant    = evTalerOfTheExample();
    const gefPayments = keyOf('Ed25519', seedOf('DE*GEF, payments'), { notAfter: NOT_AFTER, usages: [ 'payments' ] });

    parties.take('evtaler-key', parties.prepare({ createdAt: minute(13), description: 'DE*GEF adds a signing key for payments', signers: [ gefParty ],
                                                changes: [ update('ChargingStationOperator', 'DE*GEF', 'signingKeys', found(parties, 'ChargingStationOperator', 'DE*GEF', 'signingKeys'), inOrder([ gefRenewed, gefParty, gefPayments ])) ] }));

    const merchantAdded  = update('ChargingStationOperator', 'DE*GEF', 'evTaler', found(parties, 'ChargingStationOperator', 'DE*GEF', 'evTaler'), merchant);
    const poolNamesIt    = update('ChargingPool', 'DE*GEF*P1', 'paymentOptions', found(parties, 'ChargingPool', 'DE*GEF*P1', 'paymentOptions'), [ 'EVTaler' ]);
    const paying         = (description, changes, signers) => parties.prepare({ createdAt: minute(14), description, changes, signers });

    parties.keep('evtaler-merchant', paying('DE*GEF names its EV Taler merchant', [ merchantAdded ], [ gefPayments ]));
    const forPayments = { reason: "needs a signature by a signing key of the ChargingStationOperator 'DE*GEF' that may sign 'payments'!" };
    P.refused('evtaler-merchant-signed-for-party', 'A charging station operator names its EV Taler merchant, signed by its signing key for the party alone: a change of evTaler needs a key that may sign payments.', EV_TALER_BASIS,
              'evtaler-merchant-party', paying('DE*GEF names its EV Taler merchant', [ merchantAdded ], [ gefParty ]), 'evtaler-merchant', forPayments);
    P.refused('evtaler-merchant-signed-for-infrastructure', 'A charging station operator names its EV Taler merchant, signed by its signing key for infrastructure alone.', EV_TALER_BASIS,
              'evtaler-merchant-infrastructure', paying('DE*GEF names its EV Taler merchant', [ merchantAdded ], [ gefRenewed ]), 'evtaler-merchant', forPayments);
    P.refused('evtaler-merchant-signed-by-rno', 'The roaming network operator names the EV Taler merchant of a charging station operator with signing keys, signed by two holders with signing keys for the party: it signs in place of a party without signing keys only.', EV_TALER_BASIS,
              'evtaler-merchant-rno', paying('DE*GEF names its EV Taler merchant, by the roaming network operator', [ merchantAdded ], [ alphaParty, betaParty ]), 'evtaler-merchant',
              { reason: "needs a signature by a signing key of the ChargingStationOperator 'DE*GEF'!" });

    parties.keep('evtaler-both', paying('DE*GEF names its EV Taler merchant, Jena Paradies the payment option EVTaler', [ merchantAdded, poolNamesIt ], [ gefPayments, gefRenewed ]));
    const noMerchant = { reason: "The charging pool 'DE*GEF*P1' names the payment option 'EVTaler', but its operator 'DE*GEF' has no EV Taler merchant!" };
    P.refused('evtaler-pool-without-merchant', 'A charging pool names the payment option EVTaler, its operator no EV Taler merchant.', EV_TALER_BASIS,
              'evtaler-pool', paying('Jena Paradies names the payment option EVTaler', [ poolNamesIt ], [ gefRenewed ]), 'evtaler-both', noMerchant);
    P.then('evtaler-pool-before-merchant', 'One change set names the payment option EVTaler of a charging pool first, then the EV Taler merchant of its operator: checked after its last change.', EV_TALER_BASIS,
           'evtaler-pool-first', paying('Jena Paradies names the payment option EVTaler, DE*GEF its EV Taler merchant', [ poolNamesIt, merchantAdded ], [ gefRenewed, gefPayments ]));

    parties.take('evtaler-both', paying('DE*GEF names its EV Taler merchant, Jena Paradies the payment option EVTaler', [ merchantAdded, poolNamesIt ], [ gefPayments, gefRenewed ]));
    P.accepted('evtaler-merchant-and-pool', 'A charging station operator names its EV Taler merchant, signed by its key for payments, and a charging pool of it the payment option EVTaler, in one change set.', EV_TALER_BASIS);

    const merchantRemoved = unset('ChargingStationOperator', 'DE*GEF', 'evTaler', found(parties, 'ChargingStationOperator', 'DE*GEF', 'evTaler'));
    const poolNamesNone   = unset('ChargingPool', 'DE*GEF*P1', 'paymentOptions', found(parties, 'ChargingPool', 'DE*GEF*P1', 'paymentOptions'));
    const leavingTaler    = (description, changes, signers) => parties.prepare({ createdAt: minute(15), description, changes, signers });

    parties.keep('evtaler-removed', leavingTaler('Jena Paradies names no payment option, DE*GEF no EV Taler merchant', [ poolNamesNone, merchantRemoved ], [ gefRenewed, gefPayments ]));
    P.refused('evtaler-merchant-removed-while-named', 'A charging station operator removes its EV Taler merchant while a charging pool of it names the payment option EVTaler.', EV_TALER_BASIS,
              'evtaler-removed-merchant', leavingTaler('DE*GEF names no EV Taler merchant', [ merchantRemoved ], [ gefPayments ]), 'evtaler-removed', noMerchant);
    P.then('evtaler-removed-with-the-pool', 'One change set removes the EV Taler merchant of a charging station operator first, then the payment option EVTaler of its charging pool: checked after its last change.', EV_TALER_BASIS,
           'evtaler-removed-merchant-first', leavingTaler('DE*GEF names no EV Taler merchant, Jena Paradies no payment option', [ merchantRemoved, poolNamesNone ], [ gefPayments, gefRenewed ]));

    // ---- The entities a party embeds (4.1), as WWCP_POI3 applies them and WWCP_POI.TS since `1946013`: charging tariff
    //      offers, signed by a key that may sign tariffs; the groups and offers of an e-mobility provider, its own; a grid
    //      connection point handed on within a change set, the changes after it its new maintainer's (csharp-review 9);
    //      the parking data of a parking operator and the parking spaces of a charging station operator, each its own.
    S('| `tariffs` | charging tariffs, their templates and groups, charging tariff offers |', 'that a charging tariff offer is signed for tariffs');
    S('| templates, groups and charging tariff offers | the party embedding them (the parent of an `Add`)', 'who owns the groups and offers a party embeds');
    S('| parking garages, spaces, sensors and products | their parking operator (the parent of an `Add`) |', 'who owns parking data');
    S('a grid connection point an earlier change handed\non by its new maintainer', 'who owns a grid connection point handed on within a change set');
    S('| `maintainedBy` of a grid connection point | its grid operator, its maintainer, or an identity key of the RNO |', 'who changes the maintainer of a grid connection point');

    const gefTariffs        = keyOf('Ed25519', seedOf('DE*GEF, tariffs'),         { notAfter: NOT_AFTER, usages: [ 'tariffs' ] });
    const prkIdentity       = keyOf('Ed25519', seedOf('DE*PRK, identity'));
    const prkInfrastructure = keyOf('Ed25519', seedOf('DE*PRK, infrastructure'),  { notAfter: NOT_AFTER, usages: [ 'infrastructure' ] });

    parties.take('embedded-setup', parties.prepare({
        createdAt:    minute(16),
        description:  'DE*GEF adds a signing key for tariffs, an EVSE and the EVSE group Second of it; the parking operator DE*PRK; connection-1 of DE*NET, by the roaming network operator in its place',
        changes:      [ update('ChargingStationOperator', 'DE*GEF', 'signingKeys', found(parties, 'ChargingStationOperator', 'DE*GEF', 'signingKeys'), inOrder([ gefRenewed, gefParty, gefPayments, gefTariffs ])),
                        add('EVSE', { '@id': 'DE*GEF*E1*2', maxPower: 150000 }, [ 'ChargingStation', 'DE*GEF*S1' ]),
                        add('EVSEGroup', { '@id': 'DE*GEF*EG_2', name: { en: 'Second' }, EVSEIds: [ 'DE*GEF*E1*2' ] }),
                        add('ParkingOperator', party('DE*PRK', { de: 'Parken in Jena' }, [ prkIdentity ], [ prkInfrastructure ])),
                        add('GridConnectionPoint', { '@id': 'connection-1' }, [ 'GridOperator', 'DE*NET' ]) ],
        signers:      [ gefParty, gefRenewed, alphaParty, betaParty, prkIdentity ],
    }));

    // Charging tariff offers of a charging station operator: signed for tariffs, and no two covering one EVSE for the same
    // sessions at the same times (9.4).
    const offering      = (createdAt, description, changes, signers) => parties.prepare({ createdAt, description, changes, signers });
    const highwayOffer  = add('ChargingTariffOffer', { '@id': 'gef-highway', name: { en: 'Highway, ten off' }, discount: { percent: 10 }, EVSEGroupIds: [ 'DE*GEF*EG_HW' ] },
                              [ 'ChargingStationOperator', 'DE*GEF' ]);
    const offerHighway  = () => offering(minute(17), 'DE*GEF offers ten off at the EVSE group Highway', [ highwayOffer ], [ gefTariffs ]);

    parties.keep('offer-highway', offerHighway());
    P.refused('offer-signed-for-infrastructure', 'A charging station operator adds a charging tariff offer, signed by its signing key for infrastructure alone: an offer needs a key that may sign tariffs.', B('4.1'),
              'offer-highway-infrastructure', offering(minute(17), 'DE*GEF offers ten off at the EVSE group Highway', [ highwayOffer ], [ gefRenewed ]), 'offer-highway',
              { reason: "needs a signature by a signing key of the ChargingStationOperator 'DE*GEF' that may sign 'tariffs'!" });

    parties.take('offer-highway', offerHighway());
    P.accepted('offer-added', 'A charging station operator adds a charging tariff offer at an EVSE group of its own, signed by its signing key for tariffs.', `${B('4.1; 9.4')}`);

    const fiveOff = (EVSEGroupIds) => add('ChargingTariffOffer', { '@id': 'gef-five', name: { en: 'Five off' }, discount: { percent: 5 }, EVSEGroupIds }, [ 'ChargingStationOperator', 'DE*GEF' ]);
    parties.keep('offer-second', offering(minute(18), 'DE*GEF offers five off at the EVSE group Second', [ fiveOff([ 'DE*GEF*EG_2' ]) ], [ gefTariffs ]));
    P.refused('offer-overlapping', 'A charging station operator adds a charging tariff offer covering an EVSE another offer of it covers, for the same sessions at the same times.', B('9.4'),
              'offer-five-at-highway', offering(minute(18), 'DE*GEF offers five off at the EVSE group Highway', [ fiveOff([ 'DE*GEF*EG_HW' ]) ], [ gefTariffs ]), 'offer-second',
              { reason: "of the operator 'DE*GEF' overlap at the EVSE 'DE*GEF*E1*1'" });

    // The groups and offers of an e-mobility provider: its own, not of the charging station operator of its prefix.
    const ofTheProvider     = { reason: "needs a signature by a signing key of the EMobilityProvider 'DE-GEF'!" };
    const favourites        = add('EVSEGroup', { '@id': 'DE*GEF*EG_FAV', name: { en: 'Favourites' }, EVSEIds: [ 'DE*GEF*E1*1' ] }, [ 'EMobilityProvider', 'DE-GEF' ]);
    const favouritesOffer   = add('ChargingTariffOffer', { '@id': 'emp-favourites', name: { en: 'Favourites, five off' }, discount: { percent: 5 }, EVSEGroupIds: [ 'DE*GEF*EG_FAV' ] },
                                  [ 'EMobilityProvider', 'DE-GEF' ]);
    P.then('offer-of-a-provider', 'An e-mobility provider adds an EVSE group of its own and a charging tariff offer at it, signed by its signing key.', B('4.1; 9.3; 9.4'),
           'offer-provider', offering(minute(18), 'DE-GEF adds its EVSE group Favourites and five off at it', [ favourites, favouritesOffer ], [ empSigning ]));
    P.refused('offer-of-a-provider-signed-by-the-operator', 'The EVSE group and the charging tariff offer of an e-mobility provider, signed by the signing keys for infrastructure and tariffs of the charging station operator of its prefix: what a provider embeds is its own.', B('4.1; 9.3'),
              'offer-provider-by-operator', offering(minute(18), 'DE-GEF adds its EVSE group Favourites and five off at it', [ favourites, favouritesOffer ], [ gefRenewed, gefTariffs ]), 'offer-provider',
              ofTheProvider);

    const providerGroups    = [ add('ChargingStationGroup', { '@id': 'DE*GEF*SG_FAV', name: { en: 'Favourite stations' }, chargingStationIds: [ 'DE*GEF*S1' ] }, [ 'EMobilityProvider', 'DE-GEF' ]),
                                add('ChargingPoolGroup',    { '@id': 'DE*GEF*PG_FAV', name: { en: 'Favourite pools' },    chargingPoolIds:    [ 'DE*GEF*P1' ] }, [ 'EMobilityProvider', 'DE-GEF' ]) ];
    P.then('groups-of-a-provider', 'An e-mobility provider adds a charging station group and a charging pool group of its own, signed by its signing key.', B('4.1; 9.3'),
           'groups-provider', offering(minute(18), 'DE-GEF adds its groups Favourite stations and Favourite pools', providerGroups, [ empSigning ]));
    P.refused('groups-of-a-provider-signed-by-the-operator', 'The charging station group and charging pool group of an e-mobility provider, signed by the signing key for infrastructure of the charging station operator of its prefix.', B('4.1; 9.3'),
              'groups-provider-by-operator', offering(minute(18), 'DE-GEF adds its groups Favourite stations and Favourite pools', providerGroups, [ gefRenewed ]), 'groups-provider',
              ofTheProvider);

    // A grid connection point of a grid operator without keys, handed on to a charging station operator: by the roaming
    // network operator in place of the grid operator; a change of it after the handing on, in the same change set, is
    // the new maintainer's, one before it still the grid operator's (csharp-review 9, 13).
    const handedOn  = update('GridConnectionPoint', 'connection-1', 'maintainedBy', found(parties, 'GridConnectionPoint', 'connection-1', 'maintainedBy'),
                             { entityType: 'ChargingStationOperator', entityId: 'DE*GEF' });
    const named     = update('GridConnectionPoint', 'connection-1', 'name', found(parties, 'GridConnectionPoint', 'connection-1', 'name'), { en: 'Jena Paradies' });
    const pointed   = (description, changes, signers) => parties.prepare({ createdAt: minute(19), description, changes, signers });
    const POINT_BASIS = `${B('4.1, Within a change set')}; csharp-review 9, 13`;

    P.then('grid-connection-point-handed-on', 'The roaming network operator, in place of a grid operator without keys, hands a grid connection point on to a charging station operator, which names it in the same change set: the change after the handing on is the new maintainer\'s.', POINT_BASIS,
           'point-handed-on', pointed('DE*NET hands connection-1 on to DE*GEF, which names it', [ handedOn, named ], [ alphaParty, betaParty, gefRenewed ]));
    P.refused('grid-connection-point-handed-on-unsigned-by-its-maintainer', 'The roaming network operator hands a grid connection point of a grid operator without keys on to a charging station operator and names it, in one change set it alone signs: the name, changed after the handing on, is the new maintainer\'s.', POINT_BASIS,
              'point-handed-on-by-rno', pointed('DE*NET hands connection-1 on to DE*GEF and names it', [ handedOn, named ], [ alphaParty, betaParty ]), 'point-handed-on',
              { reason: "Change 1: UpdateProperty of the GridConnectionPoint 'connection-1' ('name') needs a signature by a signing key of the ChargingStationOperator 'DE*GEF'!" });
    P.then('grid-connection-point-named-then-handed-on', 'The roaming network operator names a grid connection point of a grid operator without keys, then hands it on to a charging station operator, in one change set it alone signs: the change before the handing on is still the grid operator\'s.', POINT_BASIS,
           'point-named-first', pointed('DE*NET names connection-1, then hands it on to DE*GEF', [ named, handedOn ], [ alphaParty, betaParty ]));

    // Parking data: a parking operator's own, and a parking space of a charging station operator its own.
    const parking   = (description, changes, signers) => parties.prepare({ createdAt: minute(20), description, changes, signers });
    const garage    = [ add('ParkingGarage',  { '@id': 'garage-1', name: { de: 'Parkhaus Paradies' } }, [ 'ParkingOperator', 'DE*PRK' ]),
                        add('ParkingSpace',   { '@id': 'space-1', parkingGarageId: 'garage-1' },         [ 'ParkingOperator', 'DE*PRK' ]),
                        add('ParkingProduct', { '@id': 'P1', minDuration: 0 },                           [ 'ParkingOperator', 'DE*PRK' ]) ];
    const gefSpace  = [ add('ParkingSpace', { '@id': 'gef-space-1' }, [ 'ChargingStationOperator', 'DE*GEF' ]) ];

    P.then('parking-data-added', 'A parking operator adds a parking garage, a parking space in it and a parking product, signed by its signing key for infrastructure; the parking product has no timestamps.', B('4; 4.1'),
           'parking-added', parking('DE*PRK adds the garage Parkhaus Paradies, a space in it and the product P1', garage, [ prkInfrastructure ]));
    P.refused('parking-data-signed-by-another-party', 'The parking garage, space and product of a parking operator, signed by the signing key for infrastructure of a charging station operator.', B('4.1'),
              'parking-added-by-gef', parking('DE*PRK adds the garage Parkhaus Paradies, a space in it and the product P1', garage, [ gefRenewed ]), 'parking-added',
              { reason: "needs a signature by a signing key of the ParkingOperator 'DE*PRK'!" });
    P.then('parking-space-of-an-operator', 'A charging station operator adds a parking space of its own, signed by its signing key for infrastructure.', B('4.1'),
           'gef-space', parking('DE*GEF adds the parking space gef-space-1', gefSpace, [ gefRenewed ]));
    P.refused('parking-space-of-an-operator-signed-by-a-parking-operator', 'The parking space of a charging station operator, signed by the signing key for infrastructure of a parking operator.', B('4.1'),
              'gef-space-by-prk', parking('DE*GEF adds the parking space gef-space-1', gefSpace, [ prkInfrastructure ]), 'gef-space',
              { reason: "needs a signature by a signing key of the ChargingStationOperator 'DE*GEF'!" });


    // =================================================================================================================
    //  history-epochs: three epochs, the signatures of the first checkpoint of each (11.3)
    // =================================================================================================================

    const alphaES256  = keyOf('ES256', seedOf('Alpha, ES256'),    { notAfter: NOT_AFTER, holder: 'Alpha', usages: [ 'party' ] });
    const betaEd448   = keyOf('Ed448', seedOf('Beta, Ed448', 57), { notAfter: NOT_AFTER, holder: 'Beta',  usages: [ 'party' ] });

    const epochs = generatedHistory('history-epochs',
                                    'The roaming network rn1 of DE*RNO through three epochs: the first of every algorithm, the second of ES256 and Ed25519 identified with SHA-512, the third of Ed25519 alone identified with SHA-384. Alpha signs checkpoints with an Ed25519 and an ES256 key, Beta with an Ed448 key.',
                                    networkOf(rnoOf([ [ alphaParty, alphaIdentity ], [ betaParty, betaIdentity ], [ alphaES256, alphaIdentity ], [ betaEd448, betaIdentity ] ])),
                                    leader);
    histories.push(epochs);

    const profiles = (identificationHash, signatureAlgorithms) => ({ canonicalization: S('styx-canonical-json-v1', 'the canonicalization of the profiles'), identificationHash,
                                                                      commit: CONTEXTS.commit, checkpoint: CONTEXTS.checkpoint, priceStatement: CONTEXTS.priceStatement, signatureAlgorithms });
    const by = (...keys) => keys.map(key => ({ key }));

    const renamed = (name, at) => epochs.prepare({ createdAt: at, description: `rn1: ${name.en}`, signers: [ alphaParty, betaParty ],
                                                   changes: [ update('RoamingNetwork', 'rn1', 'name', found(epochs, 'RoamingNetwork', 'rn1', 'name'), name) ] });

    epochs.take('epoch-1-commit-1', renamed({ en: 'Example of three epochs' }, minute(1)));
    epochs.takeCheckpoint('epoch-1-checkpoint-0', epochs.checkpoint({ createdAt: minute(2), signers: by(alphaParty, betaEd448), final: true, next: { epoch: 2, profiles: profiles('sha512', [ 'ES256', 'Ed25519' ]) } }));
    epochs.nextEpoch();
    epochs.takeCheckpoint('epoch-2-checkpoint-0', epochs.checkpoint({ createdAt: minute(3), signers: by(alphaParty, alphaES256), final: true, next: { epoch: 3, profiles: profiles('sha384', [ 'Ed25519' ]) } }));
    const genesis3 = epochs.nextEpoch();

    const E = replaysOf(epochs);

    // The commit of a snapshot is signed in algorithms of its epoch, as every commit taken later, anchored or not (WWCP_POI
    // b43ff1a): a snapshot of the genesis of the third epoch, of Ed25519 alone, its commit signed with Ed448, which the
    // first epoch took. Its signatures are no part of what identifies it, so that only the algorithm is refused.
    const snapshotOfGenesis3 = (name, key) => {
        const fields    = { role: 'roamingNetworkOperator', signer: leader.signer, signedAt: minute(3), algorithm: key.algorithm, keyId: key.id };
        const signature = { ...fields, value: key.sign(roleSignatureInput(CONTEXTS.commitSignature, fields, 'commit', commitAsSigned(genesis3))) };
        return epochs.keepDocument(name, { commit: { ...genesis3, signatures: [ signature ] }, roamingNetwork: epochs.head.content, epoch: { epoch: epochs.epoch.number, profiles: epochs.epoch.profiles } });
    };
    if (epochs.epoch.number !== 3 || epochs.epoch.profiles.signatureAlgorithms.join() !== 'Ed25519')
        fail('history-epochs: the third epoch is not one of Ed25519 alone');

    replay('epoch-snapshot-commit-algorithm-of-another-epoch', epochs, 'refused', 'A history started from a snapshot of the genesis of the third epoch, of Ed25519 alone, its commit signed with Ed448, which the first epoch took: the commit of a snapshot is signed in algorithms of its epoch, as every commit taken later. Signed with Ed25519, it is taken.', `${B('11.1')}; ${B('10.5')}`,
           { steps: [ { op: 'fromSnapshot', document: snapshotOfGenesis3('epoch-3-snapshot-Ed448', betaEd448) } ], control: snapshotOfGenesis3('epoch-3-snapshot', alphaParty),
             reason: `The signature algorithm 'Ed448' of a signature of the commit '${genesis3['@id']}' is not one of the epoch 3, Ed25519!` });

    // The first checkpoint of the third epoch: signed with the algorithms of either epoch, never with another one, though the
    // first epoch took it (csharp-review 14).
    const firstOfEpoch3 = epochs.checkpoint({ createdAt: minute(4), signers: by(alphaParty, alphaES256) });
    replay('epoch-first-checkpoint-algorithms-of-either', epochs, 'accepted', 'The first checkpoint of the third epoch, signed with ES256, an algorithm of the second epoch only, and Ed25519.', `${B('11.3')}; csharp-review 14`,
           { steps: epochs.steps({ op: 'takeCheckpoint', document: epochs.keep('epoch-3-checkpoint-0', firstOfEpoch3) }) });
    E.refused('epoch-first-checkpoint-algorithm-of-neither', 'The first checkpoint of the third epoch, signed with Ed448, which neither the second nor the third epoch accepts, though the first one did.', `${B('11.3')}; csharp-review 14`,
              'epoch-3-checkpoint-0-Ed448', epochs.checkpoint({ createdAt: minute(4), signers: by(alphaParty, betaEd448) }), 'epoch-3-checkpoint-0',
              { op: 'takeCheckpoint', reason: "is neither one of the epoch 3, Ed25519, nor of the epoch 2, ES256, Ed25519" });

    epochs.takeCheckpoint('epoch-3-checkpoint-0', firstOfEpoch3);
    epochs.take('epoch-3-commit-1', renamed({ en: 'Example of the third epoch' }, minute(5)));

    epochs.keep('epoch-3-checkpoint-1', epochs.checkpoint({ createdAt: minute(6), signers: by(alphaParty) }));
    E.refused('epoch-later-checkpoint-algorithm-of-before', 'A later checkpoint of the third epoch, signed with ES256, an algorithm of the second epoch only: every checkpoint but the first is signed with the algorithms of its own epoch.', `${B('11.3')}; csharp-review 14`,
              'epoch-3-checkpoint-1-ES256', epochs.checkpoint({ createdAt: minute(6), signers: by(alphaES256) }), 'epoch-3-checkpoint-1',
              { op: 'takeCheckpoint', reason: "is not one of the epoch 3, Ed25519" });

    epochs.takeCheckpoint('epoch-3-checkpoint-1', epochs.checkpoint({ createdAt: minute(6), signers: by(alphaParty) }));
    E.accepted('epochs', 'Three epochs, each started from the final checkpoint of the one before, the third with a commit and two checkpoints.', `${B('11')}; csharp-review 14`);


    // =================================================================================================================
    //  history-anchored: what a server or client takes of another server, only anchored in the trust anchor (8.5, 10.5)
    // =================================================================================================================

    quoted(SPEC, '- **Anchored:** a server or client takes a history of another server, from a checkpoint or from a snapshot of the head,', 'the anchored start of 10.5');

    // Alpha holds a second signing key for the party, Beta one ending at 08:12, after it attested and signed; a signing key
    // of "Beta" no certificate names.
    const alphaSecond   = rnoSigning('Alpha, party 2', 'Alpha', [ 'party' ]);
    const betaEnding    = keyOf('Ed25519', seedOf('Beta, party, ending'), { notAfter: minute(12), holder: 'Beta', usages: [ 'party' ] });
    const uncertified   = rnoSigning('Beta, uncertified', 'Beta', [ 'party' ]);

    const anchored = generatedHistory('history-anchored',
                                      'The roaming network rn1 of DE*RNO, the quorum of Alpha and Beta, Alpha with a second signing key for the party, Beta with one ending at 08:12: DE*GEF added, its head attested and checkpointed, as another server gives them to whoever starts from it.',
                                      networkOf(rnoOf([ [ alphaParty, alphaIdentity ], [ betaParty, betaIdentity ], [ alphaSecond, alphaIdentity ], [ betaEnding, betaIdentity ] ])),
                                      leader);
    histories.push(anchored);

    anchored.take('commit-1', anchored.prepare({
        createdAt:    minute(1),
        description:  'DE*GEF',
        changes:      [ add('ChargingStationOperator', party('DE*GEF', { en: 'GraphDefined Charging Solutions' }, [ gefIdentity ], [ gefInfrastructure ])) ],
        signers:      [ alphaParty, betaParty, gefIdentity ],
    }));

    const anchoredHead  = anchored.head;
    const rootOf        = (version) => version.commit.eTags.find(eTag => eTag[0] === 'effectiveTree');
    const parentVersion = anchoredHead.versions[0];

    /** An attestation of the head (8.5), signed by the given key at 08:10, valid for 15 minutes: of its commit and root, by DE*RNO. */
    const attestationBy = (key, { commit = anchoredHead.commit, eTag = rootOf(anchoredHead), role = 'roamingNetworkOperator', subject } = {}) => {
        const fields = { roamingNetworkId: 'rn1', commitId: commit['@id'], revision: commit.revision, eTag, role, signer: 'DE*RNO', signedAt: minute(10), validUntil: minute(25),
                         ...(subject === undefined ? {} : { subject }), algorithm: key.algorithm, keyId: key.id };
        return { ...fields, value: key.sign(attestationSignatureInput(fields)) };
    };

    // The node of DE*GEF in the tree of the head, as a subject attests it (8.5, Subject).
    const gefNode = mth(hashOf('sha256'), [ utf8(canonical(skeletonOf(byId(anchoredHead.content.chargingStationOperators, 'DE*GEF'), 'charging station operator', hashOf('sha256')))) ]).toString('hex');

    /** A snapshot of the head (8.5): the version, its commit, and the attestations given. */
    const headSnapshot = (name, attestations) =>
        anchored.keepDocument(name, { commit: anchoredHead.commit, roamingNetwork: anchoredHead.content, ...(attestations === undefined ? {} : { attestations }) });

    /** A snapshot of the checkpoint of the head (10.5), signed by the given signers at 08:02. */
    const checkpointBy       = (...signers) => anchored.checkpoint({ createdAt: minute(2), signers });
    const checkpointSnapshot = (name, checkpoint) => anchored.keepDocument(name, { commit: anchoredHead.commit, roamingNetwork: anchoredHead.content, checkpoint });

    const checkpoint0  = checkpointBy({ key: alphaParty }, { key: betaParty });

    const snapshots = {
        head:                    headSnapshot('snapshot-of-the-head',                   [ attestationBy(alphaParty), attestationBy(betaParty) ]),
        unattested:              headSnapshot('snapshot-of-the-head-unattested'),
        otherCommit:             headSnapshot('snapshot-of-the-head-other-commit',      [ attestationBy(alphaParty, { commit: parentVersion.commit }), attestationBy(betaParty, { commit: parentVersion.commit }) ]),
        otherRoot:               headSnapshot('snapshot-of-the-head-other-root',        [ attestationBy(alphaParty, { eTag: rootOf(parentVersion) }), attestationBy(betaParty, { eTag: rootOf(parentVersion) }) ]),
        keyEnding:               headSnapshot('snapshot-of-the-head-key-ending',        [ attestationBy(alphaParty), attestationBy(betaEnding) ]),
        uncertified:             headSnapshot('snapshot-of-the-head-uncertified-key',   [ attestationBy(alphaParty), attestationBy(uncertified) ]),
        oneHolder:               headSnapshot('snapshot-of-the-head-one-holder',        [ attestationBy(alphaParty), attestationBy(alphaSecond) ]),
        witness:                 headSnapshot('snapshot-of-the-head-witness',           [ attestationBy(alphaParty), attestationBy(betaParty, { role: 'witness' }) ]),
        subject:                 headSnapshot('snapshot-of-the-head-subject',           [ attestationBy(alphaParty), attestationBy(betaParty, { subject: { entityType: 'ChargingStationOperator', entityId: 'DE*GEF', digest: gefNode } }) ]),
        unreadable:              headSnapshot('snapshot-of-the-head-unreadable-attestation', [ attestationBy(alphaParty), attestationBy(betaParty), without(attestationBy(alphaSecond), 'signedAt') ]),
        attestationAsText:       headSnapshot('snapshot-of-the-head-attestation-as-text',    [ attestationBy(alphaParty), attestationBy(betaParty), canonical(attestationBy(alphaSecond)) ]),
        checkpoint:              checkpointSnapshot('snapshot-of-checkpoint-0',                  checkpoint0),
        checkpointWitnessed:     checkpointSnapshot('snapshot-of-checkpoint-0-witnessed',        checkpointBy({ key: alphaParty, role: 'witness' }, { key: betaParty, role: 'witness' })),
        checkpointUncertified:   checkpointSnapshot('snapshot-of-checkpoint-0-uncertified-key',  checkpointBy({ key: alphaParty }, { key: uncertified })),
        checkpointOneHolder:     checkpointSnapshot('snapshot-of-checkpoint-0-one-holder',       checkpointBy({ key: alphaParty }, { key: alphaSecond })),
        checkpointKeyEnding:     checkpointSnapshot('snapshot-of-checkpoint-0-key-ending',       checkpointBy({ key: alphaParty }, { key: betaEnding })),
    };

    anchored.takeCheckpoint('checkpoint-0', checkpoint0);
    replay('anchored-history', anchored, 'accepted', 'DE*GEF added to rn1, and the checkpoint of the head: the history the snapshots of anchoredSnapshots are of, taken as its server takes it.', B('4.1; 10.1'),
           { steps: anchored.steps(anchored.expectHead()) });

    /** A trust anchor of the quorum of Alpha and Beta (8.6), of rn1 or another roaming network. */
    const trustAnchorOf = (networkId = 'rn1') => canonical({ '@id': networkId, '@context': CONTEXT + 'trustAnchor/v2', urls: [ `https://hub.example/poi/RNs/${networkId}`, `https://mirror.example/poi/RNs/${networkId}` ],
                                                             keys: [ alphaIdentity.id, betaIdentity.id ], minConsensus: 2, name: { en: 'Example' } });

    const anchoredSnapshots = [];

    /**
     * A snapshot of the head or of a checkpoint another server gives, taken against a trust anchor at a point in time, or
     * refused; a refusal with its control, what it changes given otherwise, taken.
     */
    const anchoredSnapshot = (id, snapshot, expected, description, basis, { document, trustAnchor = trustAnchorOf(), at = minute(15), control, reason }) => {
        const vector = { id, description, basis, history: anchored.id, snapshot, commitAndCheckpointSignatures: 'unchecked', expected, document, trustAnchor, at };
        if (expected === 'refused') {
            vector.control = { document, trustAnchor, at, ...(control ?? fail(`${id}: a refusal without its control`)) };
            if (JSON.stringify(vector.control) === JSON.stringify({ document, trustAnchor, at }))
                fail(`${id}: the control is what is refused`);
        }
        anchoredSnapshots.push(reason === undefined ? vector : { ...vector, reason });
    };

    const anchoredBasis = B('8.5, Trust; 10.5, Anchored');
    const toTheHead     = { document: snapshots.head };

    anchoredSnapshot('anchored-head',                       'head', 'accepted', 'A snapshot of the head with attestations of its root in the role of the roaming network operator, by the signing keys of Alpha and Beta, each certified by the identity key of its holder the trust anchor names; within the validity of the attestations.', anchoredBasis,
                     { document: snapshots.head });
    anchoredSnapshot('anchored-head-unattested',            'head', 'refused',  'A snapshot of the head without attestations: the keys of the operator a version names are public and prove nothing.', anchoredBasis,
                     { document: snapshots.unattested, control: toTheHead, reason: 'No attestation of the head' });
    anchoredSnapshot('anchored-head-other-commit',          'head', 'refused',  'A snapshot of the head whose attestations name its root, but the commit and the revision of its parent.', anchoredBasis,
                     { document: snapshots.otherCommit, control: toTheHead, reason: 'of 0 holders attest the root' });
    anchoredSnapshot('anchored-head-other-root',            'head', 'refused',  'A snapshot of the head whose attestations name its commit, but the root of the version of its parent.', anchoredBasis,
                     { document: snapshots.otherRoot, control: toTheHead, reason: 'of 0 holders attest the root' });
    anchoredSnapshot('anchored-head-expired',               'head', 'refused',  'A minute after the attestations of the head ended (validUntil).', `${B('8.5, Validity')}; ${anchoredBasis}`,
                     { document: snapshots.head, at: minute(26), control: { at: minute(15) }, reason: 'of 0 holders attest the root' });
    anchoredSnapshot('anchored-head-not-yet-valid',         'head', 'refused',  'A minute before the attestations of the head were signed.', `${B('8.5, Validity')}; ${anchoredBasis}`,
                     { document: snapshots.head, at: minute(9), control: { at: minute(15) }, reason: 'of 0 holders attest the root' });
    anchoredSnapshot('anchored-head-key-ended',             'head', 'refused',  'The signing key of Beta ended (notAfter, 08:12) after it attested the head (08:10) and before the time checked, its attestation still valid; checked before it ended, the snapshot is taken.', `${B('8.5, Validity; 8.6')}; ${anchoredBasis}`,
                     { document: snapshots.keyEnding, control: { at: minute(11) }, reason: 'of 1 holder attest the root' });
    anchoredSnapshot('anchored-head-uncertified-key',       'head', 'refused',  'Beta attests the head with a signing key no certificate names, so no identity key the trust anchor names certifies it.', anchoredBasis,
                     { document: snapshots.uncertified, control: toTheHead, reason: 'of 1 holder attest the root' });
    anchoredSnapshot('anchored-head-one-holder',            'head', 'refused',  'Attested by the two signing keys of Alpha: one holder, where the trust anchor and the key statement take two.', anchoredBasis,
                     { document: snapshots.oneHolder, control: toTheHead, reason: 'of 1 holder attest the root' });
    anchoredSnapshot('anchored-head-role',                  'head', 'refused',  'Beta attests the head in the role of a witness: the roaming network operator attests its versions.', anchoredBasis,
                     { document: snapshots.witness, control: toTheHead, reason: 'of 1 holder attest the root' });
    anchoredSnapshot('anchored-head-subject',               'head', 'refused',  'Alpha attests the root of the head, Beta only the node of DE*GEF (a subject), which does not count for the head.', `${B('8.5, Subject')}; ${anchoredBasis}`,
                     { document: snapshots.subject, control: toTheHead, reason: 'of 1 holder attest the root' });
    anchoredSnapshot('anchored-head-other-network',         'head', 'refused',  'A trust anchor of another roaming network.', anchoredBasis,
                     { document: snapshots.head, trustAnchor: trustAnchorOf('rn2'), control: { trustAnchor: trustAnchorOf() }, reason: "The trust anchor is one of the roaming network 'rn2'!" });

    // The attestations of a snapshot are read as those of a proof (csharp-review 22): one that can not be read refuses it,
    // though Alpha and Beta attest its head beside it.
    quoted(SPEC, 'a snapshot whose `attestations` is not an array of attestations that can all be read is refused', 'the reading of the attestations of a snapshot of 8.5');
    anchoredSnapshot('anchored-head-unreadable-attestation', 'head', 'refused', 'A snapshot of the head attested by Alpha and Beta, and with a third attestation without its signedAt: an attestation that can not be read refuses the snapshot, as it refuses a proof.', `${B('8.5')}; ${anchoredBasis}; csharp-review 22`,
                     { document: snapshots.unreadable, control: toTheHead, reason: 'Invalid attestation' });
    anchoredSnapshot('anchored-head-attestation-not-an-object', 'head', 'refused', 'A snapshot of the head attested by Alpha and Beta, and with a third attestation given as JSON text, not as an object.', `${B('8.5')}; ${anchoredBasis}; csharp-review 22`,
                     { document: snapshots.attestationAsText, control: toTheHead, reason: 'Invalid attestation' });

    const toTheCheckpoint = { document: snapshots.checkpoint };

    anchoredSnapshot('anchored-checkpoint',                 'checkpoint', 'accepted', 'A snapshot of the checkpoint of the head, signed in the role of the roaming network operator by the signing keys of Alpha and Beta, each certified by the identity key of its holder the trust anchor names.', anchoredBasis,
                     { document: snapshots.checkpoint });
    anchoredSnapshot('anchored-checkpoint-role',            'checkpoint', 'refused',  'A snapshot of the checkpoint of the head, Alpha and Beta signing it as witnesses only.', `${B('10.2')}; ${anchoredBasis}`,
                     { document: snapshots.checkpointWitnessed, control: toTheCheckpoint, reason: 'of 0 holders sign the checkpoint' });
    anchoredSnapshot('anchored-checkpoint-uncertified-key', 'checkpoint', 'refused',  'Beta signs the checkpoint with a signing key no certificate names.', anchoredBasis,
                     { document: snapshots.checkpointUncertified, control: toTheCheckpoint, reason: 'of 1 holder sign the checkpoint' });
    anchoredSnapshot('anchored-checkpoint-one-holder',      'checkpoint', 'refused',  'The checkpoint signed by the two signing keys of Alpha: one holder, where the trust anchor and the key statement take two.', anchoredBasis,
                     { document: snapshots.checkpointOneHolder, control: toTheCheckpoint, reason: 'of 1 holder sign the checkpoint' });
    anchoredSnapshot('anchored-checkpoint-key-ended',       'checkpoint', 'refused',  'The signing key of Beta ended (notAfter, 08:12) after it signed the checkpoint (08:02) and before the time checked; checked before it ended, the snapshot is taken.', `${B('8.6')}; ${anchoredBasis}`,
                     { document: snapshots.checkpointKeyEnding, control: { at: minute(11) }, reason: 'of 1 holder sign the checkpoint' });
    anchoredSnapshot('anchored-checkpoint-other-network',   'checkpoint', 'refused',  'A trust anchor of another roaming network.', anchoredBasis,
                     { document: snapshots.checkpoint, trustAnchor: trustAnchorOf('rn2'), control: { trustAnchor: trustAnchorOf() }, reason: "The trust anchor is one of the roaming network 'rn2'!" });

    // The signatures of a checkpoint that do not verify, or are not of a role the trust anchor requires, are left out and
    // refuse nothing (S39, WWCP_POI 399b7c8): nobody blocks a checkpoint by adding a signature. A key signing it twice in
    // one role, also at another time, counts once, and so does its holder (5.4, 10.2; WWCP_POI f7b8643).
    quoted(SPEC, 'left out and refuses nothing: so nobody blocks a checkpoint by adding a signature', 'what a server takes of the signatures of a checkpoint, S39');
    quoted(SPEC, 'a quorum counting each holder once', 'a signature twice of one key, 5.4');

    const signatureOf0 = (key, { signedAt = minute(2), role = 'roamingNetworkOperator', signer = leader.signer } = {}) => {
        const fields = { role, signer, signedAt, algorithm: key.algorithm, keyId: key.id };
        return { ...fields, value: key.sign(roleSignatureInput(CONTEXTS.checkpointSignature, fields, 'checkpoint', checkpointAsSigned(checkpoint0))) };
    };
    const signedOnly = (...signatures) => ({ ...without(checkpoint0, 'signatures'), signatures });

    anchor('the signatures of checkpoint-0 as signatureOf0 makes them', canonical([ signatureOf0(alphaParty), signatureOf0(betaParty) ]), canonical(checkpoint0.signatures));

    const notItsOwn = { ...signatureOf0(alphaSecond), value: signatureOf0(alphaParty).value };
    if (verifiesWith(alphaSecond.algorithm, alphaSecond.json.key, roleSignatureInput(CONTEXTS.checkpointSignature, notItsOwn, 'checkpoint', checkpointAsSigned(checkpoint0)), notItsOwn.value) === true)
        fail('history-anchored: the signature of the second signing key of Alpha that is not its own verifies');

    const witnessElsewhere = keyOf('Ed25519', seedOf('A witness another server trusts'));
    const besides = {
        invalid:       checkpointSnapshot('snapshot-of-checkpoint-0-invalid-signature-besides', signedOnly(signatureOf0(alphaParty), signatureOf0(betaParty), notItsOwn)),
        witness:       checkpointSnapshot('snapshot-of-checkpoint-0-witness-besides',           signedOnly(signatureOf0(alphaParty), signatureOf0(betaParty), signatureOf0(witnessElsewhere, { role: 'witness', signer: 'witness.example' }))),
        twice:         checkpointSnapshot('snapshot-of-checkpoint-0-one-key-twice',             signedOnly(signatureOf0(alphaParty), signatureOf0(alphaParty, { signedAt: minute(3) }))),
        twiceBesides:  checkpointSnapshot('snapshot-of-checkpoint-0-one-key-twice-besides',     signedOnly(signatureOf0(alphaParty), signatureOf0(alphaParty, { signedAt: minute(3) }), signatureOf0(betaParty))),
    };
    const S39_BASIS = `${B('10.2')}; ${anchoredBasis}`;

    anchoredSnapshot('anchored-checkpoint-invalid-signature-besides', 'checkpoint', 'accepted', 'A snapshot of the checkpoint of the head signed by Alpha and Beta in the role of the roaming network operator, and by the second signing key of Alpha with a value that is not its signature: a signature that does not verify is left out and refuses nothing (S39).', S39_BASIS,
                     { document: besides.invalid });
    anchoredSnapshot('anchored-checkpoint-witness-besides',           'checkpoint', 'accepted', 'A snapshot of the checkpoint of the head signed by Alpha and Beta in the role of the roaming network operator, and by a witness with a key the trust anchor does not know: a witness one server trusts and another one does not keeps no checkpoint from the other one (S39).', S39_BASIS,
                     { document: besides.witness });
    anchoredSnapshot('anchored-checkpoint-one-key-twice',             'checkpoint', 'refused',  'The checkpoint signed by the signing key of Alpha twice, at 08:02 and 08:03: a key signing twice in one role counts once, its holder once, where the trust anchor and the key statement take two.', `${B('5.4; 10.2')}; ${anchoredBasis}`,
                     { document: besides.twice, control: toTheCheckpoint, reason: 'of 1 holder sign the checkpoint' });
    anchoredSnapshot('anchored-checkpoint-one-key-twice-besides',     'checkpoint', 'accepted', 'The checkpoint signed by the signing key of Alpha twice, at 08:02 and 08:03, and by Beta: the second signature of a key in its role adds nothing, and refuses nothing.', `${B('5.4; 10.2')}; ${anchoredBasis}`,
                     { document: besides.twiceBesides });

    // Every document a replay names is one of its history, and the control of a refusal another than the one refused.
    for (const vector of replays) {
        const documents = histories.find(history => history.id === vector.history).documents;
        for (const name of [ ...vector.steps.map(step => step.document).filter(Boolean), ...(vector.control === undefined ? [] : [ vector.control ]) ])
            if (documents[name] === undefined)
                fail(`${vector.id}: no document ${name} in ${vector.history}`);
        if (vector.control !== undefined && documents[vector.control] === documents[vector.steps.at(-1).document])
            fail(`${vector.id}: the refused document is its control`);
    }

    for (const vector of anchoredSnapshots)
        for (const name of [ vector.document, ...(vector.control === undefined ? [] : [ vector.control.document ]) ])
            if (anchored.documents[name] === undefined)
                fail(`${vector.id}: no document ${name} in ${vector.history}`);


    return vectorFile(
        'WWCP POI 3 SPECIFICATION.md, sections 4, 5, 8.5, 10 and 11 (libs/WWCP_POI/SPECIFICATION.md)',
        'Small histories the generator made and signed, with the Ed25519 keys of section 6 and keys of seeds of its own (Ed25519, Ed448, ES256 after RFC 6979): their documents as JSON text, to be read as POI reads JSON, and replays taking them step by step. A replay "accepted" takes every step; one "refused" takes every step but its last, which it refuses (naming "reason", where both implementations word it alike), and takes "control" in place of the last one, the document refused but for what the replay is about. Anchored snapshots: a snapshot of the head or of a checkpoint another server gives, a history started from it only anchored in the trust anchor at the time "at" (10.5, Anchored); a refusal takes its "control", the snapshot, the trust anchor and the time with what it changes given otherwise.',
        { histories:          ids(histories.map(history => ({ id: history.id, description: history.description, documents: history.documents })), 'histories'),
          replays:            ids(replays, 'replays'),
          anchoredSnapshots:  ids(anchoredSnapshots, 'anchoredSnapshots') });

}


// =====================================================================================================================
//  8. The QI-Digital documents of example A14: the papers of a meter, checked against QA
// =====================================================================================================================
//
// What example A14 published in the frozen run: the digital certificates of conformity of the PTB for the SM-3 (module B)
// and for the quality system of SAALE (module D), the digital declaration of conformity of SAALE and the digital
// calibration certificate of EM-LAB for the meter of DE*GEF*E2*1, each signed by its issuer with a key of QA. The keys of
// the run are private: what needs a valid signature over other content, QA patched gives instead - the roaming network
// is an input of the check - and the checks that look at no signature, a declaration against a certificate and a
// certificate covering a meter, take documents patched.

const EXAMPLE_A14  = 'libs/WWCP_POI/examples/exampleA14.md';
const QI_DIGITAL   = 'libs/WWCP_POI/WWCP_POI3/RoamingNetwork/QIDigital';

/** A copy of a document with a JSON patch (RFC 6902: add, replace, remove) applied, as the harnesses apply it. */
function applyPatch(document, patch, where) {
    const copy = structuredClone(document);
    for (const { op, path, value } of patch) {
        const tokens  = path.split('/').slice(1).map(token => token.replaceAll('~1', '/').replaceAll('~0', '~'));
        const parent  = at(copy, tokens.slice(0, -1).map(token => '/' + token.replaceAll('~', '~0').replaceAll('/', '~1')).join(''));
        const last    = tokens.at(-1);
        if (op !== 'add' && !(last in parent))
            fail(`${where}${path}: the patch ${op}s nothing`);
        if (op === 'replace' && JSON.stringify(parent[last]) === JSON.stringify(value))
            fail(`${where}${path}: the patch changes nothing`);
        if (Array.isArray(parent)) {
            const index = last === '-' ? parent.length : Number(last);
            if      (op === 'remove') parent.splice(index, 1);
            else if (op === 'add')    parent.splice(index, 0, structuredClone(value));
            else                      parent[index] = structuredClone(value);
        }
        else if (op === 'remove') delete parent[last];
        else                      parent[last] = structuredClone(value);
    }
    return copy;
}

function qiDigitalVectors() {

    const QA    = 'published/QA.json';
    const B     = 'published/PTB-DE-26-M-PTB-0108.json';
    const D     = 'published/PTB-DE-26-QS-PTB-0042.json';
    const DDOC  = 'published/SAALE-DoC-SM-3-2026-01.json';
    const DCC   = 'published/EM-LAB-DCC-2026-0815.json';

    const KINDS    = { [B]: 'certificateOfConformity', [D]: 'certificateOfConformity', [DDOC]: 'declarationOfConformity', [DCC]: 'calibrationCertificate' };
    const ISSUERS  = { [B]: 'PTB', [D]: 'PTB', [DDOC]: 'SAALE', [DCC]: 'EM-LAB' };

    const qa        = jsonRun(QA);
    const documents = Object.fromEntries(Object.keys(KINDS).map(file => [ file, jsonRun(file) ]));

    // The anchor: each document signed by a key of its issuer in QA, over its signature input as WWCP_POI3 writes it
    // (AQIDigitalDocument): its JSON-LD context, its content and its signature without its value, in canonical JSON.
    const signingKeys = new Map([ ...qa.conformityAssessmentBodies, ...qa.energyMeterManufacturers ].flatMap(party => (party.signingKeys ?? []).map(key => [ key['@id'], { party: party['@id'], key } ])));
    for (const file of Object.keys(KINDS)) {
        const document  = parseRaw(readRun(file));
        const signing   = signingKeys.get(document.signature?.keyId) ?? fail(`${file}: signed by no signing key of QA`);
        if (signing.party !== ISSUERS[file])
            fail(`${file}: signed by a key of ${signing.party}, not of its issuer ${ISSUERS[file]}`);
        if (verifiesWith(document.signature.algorithm, signing.key.key, canonical({ ...document, signature: without(document.signature, 'value') }), document.signature.value) !== true)
            fail(`anchor: the signature of ${file} (${document.signature.algorithm}) does not verify over its input as WWCP_POI3 writes it`);
    }

    quoted(EXAMPLE_A14, 'each of a conformity assessment body of `QA` with its number, notified for its', 'what a certificate of conformity is checked against');
    quoted(EXAMPLE_A14, 'signed by a key of the manufacturer of its model that may sign `models`; each notified body it names', 'what a declaration of conformity is checked against');
    quoted(EXAMPLE_A14, 'signed by a key of its laboratory that may sign `certificates`; its item the meter of', 'what a calibration certificate is checked against');
    quoted(EXAMPLE_A14, 'A certificate of module D, D1, E, E1, H or H1 names a manufacturer, one of module B, F, F1 or G a model:', 'which certificates name a manufacturer');

    // Where the vectors patch QA and the documents, each guarded: a pointer that names another thing fails here.
    const named   = (document, pointer, id, what) => at(document, `${pointer}/@id`) === id ? pointer : fail(`${what}#${pointer} is not ${id}`);
    const emLab   = named(qa, '/conformityAssessmentBodies/1', 'EM-LAB', QA);
    const ptb     = named(qa, '/conformityAssessmentBodies/2', 'PTB', QA);
    const saale   = named(qa, '/energyMeterManufacturers/1', 'SAALE', QA);
    const sm3     = named(qa, `${saale}/energyMeterModels/0`, 'SM-3', QA);
    const acMeter = named(qa, '/chargingStationOperators/0/energyMeterTemplates/0', 'DE*GEF*EMT_AC', QA);
    const keyOf_  = (party, keyId) => `${party}/signingKeys/${at(qa, `${party}/signingKeys`).findIndex(key => key['@id'] === keyId)}`;
    const labKey  = named(qa, keyOf_(emLab, documents[DCC].signature.keyId),  documents[DCC].signature.keyId,  QA);
    const ddocKey = named(qa, keyOf_(saale, documents[DDOC].signature.keyId), documents[DDOC].signature.keyId, QA);
    const imax    = '/measurementResults/0/results/3';

    if (at(documents[DCC], `${imax}/name/en`) !== 'Imax' || at(documents[DCC], `${imax}/quantities/1/refType`) !== 'basic_measurementError')
        fail(`${DCC}#${imax}: not the error at Imax`);
    if (at(qa, `${ptb}/notifiedBodyNumber`) !== '0102' || JSON.stringify(at(qa, `${ptb}/notifiedFor`)) !== '["MID"]')
        fail(`${QA}#${ptb}: not the notified body 0102 for the MID`);
    if (JSON.stringify(at(qa, `${sm3}/firmwareVersions`)) !== '["1.0.7"]' || at(qa, `${acMeter}/firmwareVersion`) !== '1.0.7')
        fail(`${QA}: the SM-3 and the template of the AC meter are no longer on the firmware 1.0.7`);

    // ---- A case: the document, and what the check takes besides it.

    const run      = (file, patch = []) => (applyPatch(jsonRun(file), patch, file), { file, pointer: '', patch });
    const network  = (patch = []) => run(QA, patch.length === 0 ? [] : [ { op: 'remove', path: '/eTags' }, ...patch ]);

    const caseOf = (check, file, { document = [], text, network: patch = [], at: time = AT, certificate, evseId = 'DE*GEF*E2*1' } = {}) => ({
        document: text === undefined ? run(file, document) : { text },
        ...(check === 'verify'       ? { network: network(patch), at: time }                                           : {}),
        ...(check === 'certificate'  ? { certificate: run(certificate.file, certificate.patch) }                       : {}),
        ...(check === 'cover'        ? { network: network(patch), chargingStationOperatorId: 'DE*GEF', evseId }        : {}),
    });

    const vectors  = [];
    const BASIS    = `${EXAMPLE_A14}, 5; ${QI_DIGITAL}`;

    const take = (id, check, file, description, given = {}) =>
        vectors.push({ id, kind: KINDS[file], check, expected: 'accepted', basis: BASIS, description, ...caseOf(check, file, given) });

    // A refusal takes its control: the same check of the documents of the run, against QA as published, at AT.
    const refuse = (id, check, file, description, reason, given, more = {}) => {
        const refused  = caseOf(check, file, given);
        const control  = caseOf(check, file, given.certificate === undefined ? {} : { certificate: { file: given.certificate.file } });
        if (JSON.stringify(refused) === JSON.stringify(control))
            fail(`${id}: the refusal is its control`);
        vectors.push({ id, kind: KINDS[file], check, expected: 'refused', basis: BASIS, description, ...(reason === undefined ? {} : { reason }), ...refused, control, ...more });
    };

    // ---- Taken: the papers of the meter, as example A14 checks them (5).

    take('qid-type-examination',                 'verify',       B,    'The EU-type examination certificate of the SM-3 (module B), against QA: of the PTB, the notified body 0102 for the MID, valid at AT, for a model of SAALE in revisions and versions it has, signed by the key of the PTB for certificates (ML-DSA-65).');
    take('qid-quality-system',                   'verify',       D,    'The approval of the quality system of SAALE (module D), against QA: for an energy meter manufacturer of QA, scope MI-003, signed by the key of the PTB for certificates.');
    take('qid-declaration',                      'verify',       DDOC, 'The EU declaration of conformity of the SM-3, against QA: signed by the key of SAALE for its models (ES256), each notified body it names one of QA with its number.');
    take('qid-calibration',                      'verify',       DCC,  'The calibration certificate of the meter of DE*GEF*E2*1, against QA: of EM-LAB, signed by its key for certificates, its item the meter as QA names it at runtime.');
    take('qid-declaration-type-examination',     'certificate',  DDOC, 'The declaration against the EU-type examination certificate it names: of the notified body and the module it names it with, under one of its legislations, for its model in all its revisions and versions.', { certificate: { file: B } });
    take('qid-declaration-quality-system',       'certificate',  DDOC, 'The declaration against the approval of the quality system it names: of the manufacturer of its model, of its kind, with energy meters in its scope.', { certificate: { file: D } });
    take('qid-type-examination-covers-meter',    'cover',        B,    'The EU-type examination certificate covers the meter of DE*GEF*E2*1 as QA names it at runtime: its model, hardware revision and firmware version.');
    take('qid-quality-system-covers-meter',      'cover',        D,    'The approval of the quality system covers the meter of DE*GEF*E2*1: an energy meter of SAALE, of MI-003.');
    take('qid-declaration-certificate-in-lower-case', 'certificate', DDOC, 'The declaration against the EU-type examination certificate, its @id written in lower case: identifications are compared without case (DigitalCertificateOfConformity_Id), the certificate is the one it names.', { certificate: { file: B, patch: [ { op: 'replace', path: '/@id', value: documents[B]['@id'].toLowerCase() } ] } });

    // ---- Refused: changed after it was signed, or not signed by its issuer as it must be.

    refuse('qid-calibration-changed',            'verify', DCC,  'Another error at Imax, changed after it was signed (example A14, 6a): its signature is not the one of its content.', "The signature of the digital calibration certificate 'DCC-2026-0815' is invalid", { document: [ { op: 'replace', path: `${imax}/quantities/1/value`, value: -0.12 } ] });
    refuse('qid-declaration-changed',            'verify', DDOC, 'Another place of issue, changed after it was signed.', "The signature of the digital declaration of conformity 'DoC-SM-3-2026-01' is invalid", { document: [ { op: 'replace', path: '/placeOfIssue', value: 'Halle' } ] });
    refuse('qid-type-examination-changed',       'verify', B,    'Valid a year longer, changed after it was signed.', "The signature of the digital certificate of conformity 'DE-26-M-PTB-0108' is invalid", { document: [ { op: 'replace', path: '/validUntil', value: '2037-10-27T17:20:56.787Z' } ] });
    refuse('qid-calibration-not-signed',         'verify', DCC,  'Without its signature.', "The digital calibration certificate 'DCC-2026-0815' is not signed", { document: [ { op: 'remove', path: '/signature' } ] });
    refuse('qid-calibration-key-of-another-party', 'verify', DCC, 'Naming the key of the PTB for certificates as its signing key: a calibration certificate is signed by a key of its laboratory.', "is no signing key of the calibration laboratory 'EM-LAB'", { document: [ { op: 'replace', path: '/signature/keyId', value: documents[B].signature.keyId } ] });

    // ---- Refused: what WWCP_POI3 refuses to read (QIDigitalJSON).

    refuse('qid-calibration-unknown-property',   'verify', DCC,  'A property a calibration certificate does not have: unsigned, it would travel with a signed document.', "Unknown property 'x' of a digital calibration certificate!", { document: [ { op: 'add', path: '/x', value: 1 } ] });
    refuse('qid-calibration-context',            'verify', DCC,  'Another JSON-LD context, which names another kind or version of document.', 'The JSON-LD context of a digital calibration certificate must be', { document: [ { op: 'replace', path: '/@context', value: 'https://open.charging.cloud/contexts/wwcp/qiDigital/digitalCalibrationCertificate/v2' } ] });
    refuse('qid-calibration-timestamp',          'verify', DCC,  'The end of the calibration written with an offset, the same instant: a timestamp of a QI-Digital document is written as it is signed, in UTC with milliseconds.', 'must be written as yyyy-MM-ddTHH:mm:ss.fffZ!', { document: [ { op: 'replace', path: '/endPerformanceDate', value: '2026-11-05T20:43:46.678+02:00' } ] });
    refuse('qid-type-examination-not-notified',  'verify', B,    'The EU-type examination certificate issued under the RED, for which QA does not notify the PTB: the body is checked before the signature, which no longer verifies.', "is not notified for the RED", { document: [ { op: 'replace', path: '/legislation', value: { name: 'RED', act: 'Directive 2014/53/EU' } } ] });
    refuse('qid-calibration-coverage-factor',    'verify', DCC,  'The error at Imax with a coverage factor and probability, but without the expanded uncertainty they are of.', 'is one of an expanded uncertainty', { document: [ { op: 'remove', path: `${imax}/quantities/1/expandedUncertainty` } ] });
    refuse('qid-calibration-location-lower-case', 'verify', DCC, 'The performance location written "customer", not as it is named: a name is read as it is written, without case only where it is compared.', "Invalid performance location 'customer'!", { document: [ { op: 'replace', path: '/performanceLocation', value: 'customer' } ] });
    refuse('qid-calibration-location-number',     'verify', DCC, 'The performance location written "1", the number Customer has in WWCP_POI3: a name is read by its name.', "Invalid performance location '1'!", { document: [ { op: 'replace', path: '/performanceLocation', value: '1' } ] });
    refuse('qid-quality-system-names-a-model',   'verify', D,    'The approval of a quality system (module D) naming the model SM-3 as well as its manufacturer: a certificate of module D names a manufacturer, not a model.', 'approves the quality system of a manufacturer and names it, not a model', { document: [ { op: 'add', path: '/model', value: documents[B].model } ] });
    refuse('qid-type-examination-names-a-manufacturer', 'verify', B, 'The EU-type examination certificate (module B) naming SAALE in place of its model: a certificate of module B names a model, not a manufacturer.', 'is for a model and names it, not a manufacturer', { document: [ { op: 'remove', path: '/model' }, { op: 'add', path: '/manufacturer', value: documents[D].manufacturer } ] });

    // ---- Refused: the documents as signed, against QA as it would be otherwise.

    refuse('qid-type-examination-other-number',  'verify', B,    'QA naming the PTB the notified body 0103: the certificate is of the notified body 0102.', "is the notified body '0103', not '0102'", { network: [ { op: 'replace', path: `${ptb}/notifiedBodyNumber`, value: '0103' } ] });
    refuse('qid-type-examination-firmware-of-no-model', 'verify', B, 'QA with the SM-3 on the firmware 1.0.8 alone, and the template of the AC meter with it: the certificate is for the firmware 1.0.7, which the model no longer has.', "The firmware version '1.0.7' is none of the model 'SM-3' of 'SAALE'!", { network: [ { op: 'replace', path: `${sm3}/firmwareVersions`, value: [ '1.0.8' ] }, { op: 'replace', path: `${acMeter}/firmwareVersion`, value: '1.0.8' } ] });
    refuse('qid-calibration-meter-updated',      'verify', DCC,  'QA with the meter of DE*GEF*E2*1 on the firmware 1.0.8 since, a version of the SM-3 as well: a meter changed since is no longer the one calibrated.', "runs the firmware version '1.0.8', not '1.0.7'!", { network: [ { op: 'replace', path: `${sm3}/firmwareVersions`, value: [ '1.0.7', '1.0.8' ] }, { op: 'replace', path: `${acMeter}/firmwareVersion`, value: '1.0.8' } ] });
    refuse('qid-calibration-without-laboratory', 'verify', DCC,  'QA without EM-LAB: the laboratory of a calibration certificate is a conformity assessment body of the roaming network.', "The calibration laboratory 'EM-LAB' of the digital calibration certificate 'DCC-2026-0815' is no conformity assessment body of the roaming network 'QA'!", { network: [ { op: 'remove', path: emLab } ] });
    refuse('qid-calibration-key-for-party',      'verify', DCC,  'QA with the key EM-LAB signed with for its own properties only: a calibration certificate is signed by a key that may sign certificates.', "may not sign 'certificates', only 'party'", { network: [ { op: 'replace', path: `${labKey}/usages`, value: [ 'party' ] } ] });
    refuse('qid-calibration-key-ended-before',   'verify', DCC,  'QA with the key EM-LAB signed with ended before it signed.', ", when the digital calibration certificate 'DCC-2026-0815' was signed!", { network: [ { op: 'replace', path: `${labKey}/notAfter`, value: '2026-11-05T19:43:46.800Z' } ] });
    refuse('qid-declaration-key-of-no-manufacturer', 'verify', DDOC, 'QA without the key SAALE signed with for its models: a declaration is signed by a key of the manufacturer of its model.', "is no signing key of the energy meter manufacturer 'SAALE'", { network: [ { op: 'remove', path: ddocKey } ] });

    // ---- Refused: at another time.

    refuse('qid-quality-system-expired',         'verify', D,    'After the approval of the quality system ended (validUntil, three years).', "'DE-26-QS-PTB-0042' is not valid at 2029-11-06T00:00:00.000Z!", { at: '2029-11-06T00:00:00.000Z' });
    refuse('qid-calibration-key-ended',          'verify', DCC,  'After the key EM-LAB signed with ended (notAfter, a year): the key is valid when it signed and when the certificate is checked.', "of the calibration laboratory 'EM-LAB' is not valid at 2027-11-06T00:00:00.000Z!", { at: '2027-11-06T00:00:00.000Z' });

    // ---- Refused: the declaration against a certificate it does not name as it is. No signature is looked at here, the
    //      certificate's own check tells whether it is valid.

    refuse('qid-declaration-no-such-certificate', 'certificate', DDOC, 'A certificate the declaration does not name: DE-26-M-PTB-0109.', "names no certificate 'DE-26-M-PTB-0109'", { certificate: { file: B, patch: [ { op: 'replace', path: '/@id', value: 'DE-26-M-PTB-0109' } ] } });
    refuse('qid-declaration-certificate-of-another-body', 'certificate', DDOC, 'The EU-type examination certificate as one of the BSI: the declaration names it as one of the notified body 0102, the PTB.', "is one of 'BSI', not of the notified body 0102 'PTB'", { certificate: { file: B, patch: [ { op: 'replace', path: '/conformityAssessmentBodyId', value: 'BSI' } ] } });
    refuse('qid-declaration-certificate-of-another-module', 'certificate', DDOC, 'The EU-type examination certificate as one of module F: the declaration names it with module B.', "is one of the module F, not B!", { certificate: { file: B, patch: [ { op: 'replace', path: '/module', value: 'F' } ] } });
    refuse('qid-declaration-certificate-under-another-legislation', 'certificate', DDOC, 'The EU-type examination certificate issued under the RED, none of the legislations of the declaration.', 'is issued under the RED, none of the legislations of', { certificate: { file: B, patch: [ { op: 'replace', path: '/legislation', value: { name: 'RED', act: 'Directive 2014/53/EU' } } ] } });
    refuse('qid-declaration-firmware-not-covered', 'certificate', DDOC, 'The EU-type examination certificate for the firmware 1.0.8 only: the declaration is for the firmware 1.0.7 as well.', "does not cover the firmware version '1.0.7'", { certificate: { file: B, patch: [ { op: 'replace', path: '/model/firmwareVersions', value: [ '1.0.8' ] } ] } });
    refuse('qid-declaration-quality-system-of-another-manufacturer', 'certificate', DDOC, 'The approval of the quality system of KERNBERG: the declaration is of a model of SAALE.', "approves the quality system of the energy meter manufacturer 'KERNBERG'", { certificate: { file: D, patch: [ { op: 'replace', path: '/manufacturer/manufacturerId', value: 'KERNBERG' } ] } });

    // ---- Refused: a meter the certificates do not cover (example A14, 6b).

    refuse('qid-type-examination-other-meter',   'cover', B, 'The meter of DE*GEF*E1*1, a KDM-500 of KERNBERG: the EU-type examination certificate covers the SM-3 only.', "The energy meter 'DE*GEF*M1*1' is no 'SM-3' of 'SAALE'!", { evseId: 'DE*GEF*E1*1' });
    refuse('qid-quality-system-other-meter',     'cover', D, 'The meter of DE*GEF*E1*1: the approval of the quality system covers the meters of SAALE only.', "The energy meter 'DE*GEF*M1*1' is none of 'SAALE'!", { evseId: 'DE*GEF*E1*1' });
    refuse('qid-type-examination-meter-updated', 'cover', B, 'The meter of DE*GEF*E2*1 in QA with it on the firmware 1.0.8, a version of the SM-3 as well: the certificate covers the SM-3 in the firmware 1.0.7.', "The firmware version '1.0.8' of the energy meter 'DE*GEF*M2*1' is none the model 'SM-3' is covered in!", { network: [ { op: 'replace', path: `${sm3}/firmwareVersions`, value: [ '1.0.7', '1.0.8' ] }, { op: 'replace', path: `${acMeter}/firmwareVersion`, value: '1.0.8' } ] });

    // ---- Refused: a whole number beyond what WWCP_POI3 holds as one (Int64).
    //      Given as JSON text: a patch would carry the number as JavaScript reads it, 9223372036854776000.

    const beyondInt64 = readRun(DCC).replaceAll('\r\n', '\n').replace('"coverageFactor": 2,', '"coverageFactor": 9223372036854775808,');
    if (!beyondInt64.includes('9223372036854775808') || beyondInt64.split('9223372036854775808').length !== 2)
        fail(`${DCC}: no coverage factor 2 to write beyond Int64`);
    refuse('qid-calibration-number-beyond-int64', 'verify', DCC, 'The coverage factor of the error at Imin written as 2^63, one beyond the whole numbers WWCP_POI3 holds as one (Int64). Both refuse it, in words of their own.', undefined, { text: beyondInt64 });

    // ---- Refused: a text of no language, or one that is no text. Left out while reading, it would be no part of what is
    //      signed, and the signature would still verify - unsigned, it would travel with a signed document (D10, fixed).

    refuse('qid-calibration-text-of-no-language', 'verify', DCC, 'The name of the measurement with a text in "xx", no language.', "'xx' is no language!", { document: [ { op: 'add', path: '/measurementResults/0/name/xx', value: 'Messfehler der Wirkenergie' } ] });
    refuse('qid-calibration-text-not-a-text',     'verify', DCC, 'The name of the measurement with a number for its text in "de".', "the text in 'de' must be a text!", { document: [ { op: 'add', path: '/measurementResults/0/name/de', value: 5 } ] });

    // ---- The calibration certificate of a charging station, signed anew (csharp-review 23). The run holds the one of a
    //      meter only, signed by a key of EM-LAB that is private. This one the generator signs with a key of its own for
    //      certificates, which QA patched gives EM-LAB besides its own: the meter's certificate of the run, of the station
    //      DE*GEF*S2 instead, as QA names it at runtime - the manufacturer, model and versions of its template, the serial
    //      number QA patched gives the station alone (no template gives it).

    const stationOf = named(qa, '/chargingStationOperators/0/chargingPools/0/chargingStations/1', 'DE*GEF*S2', QA);
    const stAC      = named(qa, '/chargingStationOperators/0/chargingStationTemplates/0', 'DE*GEF*ST_AC', QA);
    const station   = at(qa, stationOf);
    const template  = at(qa, stAC);

    if (JSON.stringify(station.templateIds) !== '["DE*GEF*ST_AC"]' || [ 'manufacturerId', 'modelId', 'serialNumber', 'hardwareRevision', 'firmwareVersion' ].some(property => property in station))
        fail(`${QA}#${stationOf}: not a station of the template DE*GEF*ST_AC alone`);

    const SERIAL    = 'GD-AC44-2026-0002';
    const labCerts  = keyOf('Ed25519', seedOf('EM-LAB, certificates'), { notAfter: at(qa, `${labKey}/notAfter`), usages: [ 'certificates' ] });
    const labKeys   = at(qa, `${emLab}/signingKeys`);
    const keyAt     = labKeys.filter(key => key['@id'] < labCerts.id).length;

    const item      = { type: 'ChargingStation', id: station['@id'], manufacturerId: template.manufacturerId, modelId: template.modelId, serialNumber: SERIAL,
                        hardwareRevision: template.hardwareRevision, firmwareVersion: template.firmwareVersion };
    const raw       = parseRaw(readRun(DCC));
    const unsigned  = { signedAt: '2026-11-05T19:44:00.000Z', algorithm: labCerts.algorithm, keyId: labCerts.id };
    const signature = { ...unsigned, value: labCerts.sign(canonical({ ...raw, '@id': 'DCC-2026-0816', item, signature: unsigned })) };

    if (verifiesWith(signature.algorithm, labCerts.json.key, canonical({ ...raw, '@id': 'DCC-2026-0816', item, signature: unsigned }), signature.value) !== true)
        fail('anchor: the calibration certificate of the station does not verify');

    const ofStation   = [ { op: 'replace', path: '/@id', value: 'DCC-2026-0816' }, { op: 'replace', path: '/item', value: item }, { op: 'replace', path: '/signature', value: signature } ];
    const withKey     = { op: 'add', path: `${emLab}/signingKeys/${keyAt}`, value: labCerts.json };
    const serialOf    = (serialNumber) => ({ op: 'add', path: `${stationOf}/serialNumber`, value: serialNumber });
    const atStation   = caseOf('verify', DCC, { document: ofStation, network: [ withKey, serialOf(SERIAL) ] });

    // Refused but for what it is about: its control the certificate against QA with the key and the serial number.
    const refuseOfStation = (id, description, reason, network, more = {}) =>
        vectors.push({ id, kind: KINDS[DCC], check: 'verify', expected: 'refused', basis: BASIS, description, reason, ...caseOf('verify', DCC, { document: ofStation, network }), control: atStation, ...more });

    vectors.push({ id: 'qid-calibration-station', kind: KINDS[DCC], check: 'verify', expected: 'accepted', basis: BASIS,
                   description: `A calibration certificate of the charging station DE*GEF*S2, signed by a key of EM-LAB for certificates, against QA with that key and the station with the serial number ${SERIAL}: its item the station as QA names it at runtime, with its serial number.`,
                   ...atStation });

    refuseOfStation('qid-calibration-station-key-of-no-laboratory', 'The calibration certificate of the station against QA without the key it was signed with: a calibration certificate is signed by a key of its laboratory.',
                    "is no signing key of the calibration laboratory 'EM-LAB'", [ serialOf(SERIAL) ]);
    refuseOfStation('qid-calibration-station-replaced', 'The calibration certificate of the station against QA with the station of another serial number, replaced by another one of the same model and versions: it is not the one calibrated.',
                    `has the serial number 'GD-AC44-2026-0003', not '${SERIAL}'!`, [ withKey, serialOf('GD-AC44-2026-0003') ]);
    refuseOfStation('qid-calibration-station-without-serial-number', 'The calibration certificate of the station against QA naming no serial number of the station: the station of the certificate is one of a serial number.',
                    `has the serial number '', not '${SERIAL}'!`, [ withKey ]);

    return vectorFile(
        `WWCP POI 3: the QI-Digital documents, a proof of concept (${QI_DIGITAL}), as example A14 (${EXAMPLE_A14}) published them in one run: test-vectors/runs/${RUN}`,
        'The papers of the meter of DE*GEF*E2*1 as their issuers signed them: the digital certificates of conformity of the PTB, the digital declaration of conformity of SAALE and the digital calibration certificate of EM-LAB. A vector names its document (file, JSON pointer, JSON patch; or text) and its check: "verify" against the roaming network "network" at "at", "certificate" the declaration against the certificate of conformity "certificate", "cover" the certificate of conformity covering the energy meter of the EVSE "evseId" of "chargingStationOperatorId" as "network" names it at runtime. A refusal while reading the document is a refusal; the other inputs must read. A refusal takes its "control" first, the same check with the documents of the run, against QA as published, at "at", and names its "reason" where both implementations word it alike.',
        { run: `runs/${RUN}`, at: AT, vectors: ids(vectors, 'poi-qidigital.json') });

}


// =====================================================================================================================
//  9. The verifier extensions of WWCP_POI.TS 0.2.0 (experimental): the fixtures of ChargyWebApp, frozen
// =====================================================================================================================
//
// What WWCP_POI.TS 0.2.0 verifies beyond SPECIFICATION.md, and WWCP_POI3 since 89d2e02 as it does (WWCP_POI3/Verifier):
// the key of the meter of an EVSE, historical meter evidence, prices bound to a session, receipts of witnesses that a
// price was public before it, trust transitions and the keys a CPO signs its documents with. SPECIFICATION.md names only
// the usages chargeTransparencyRecords and witnessPublications; both READMEs call the rest experimental. The documents
// are the fixtures of ChargyWebApp fc513cd (tests/fixtures), which its generators made with WWCP_POI.TS itself and keys
// of public seeds - Ed25519 41 to 44 and others, ML-DSA-65, the published P-256 test key of a meter -, frozen in
// runs/chargy-fc513cd: their ECDSA signatures are not deterministic. Before a vector takes anything of them, this script
// checks what they claim with node:crypto alone: the hashes of their provenance, every signature over its input, the
// roots of the proofs of a station and of the inclusion proofs of a checkpoint, the digests the evidence binds.

const CHARGY          = 'chargy-fc513cd';
const CHARGY_DIR      = join(OUT, 'runs', CHARGY);
const CHARGY_SETS     = [ 'POISession', 'POIHistory', 'POIPrices', 'POIPublication', 'POITrustTransitions' ];
const VERIFIER        = 'libs/WWCP_POI/WWCP_POI3/Verifier';

/** The vector files WWCP_POI.TS 0.2.0 (tests/vectors) and WWCP_POI3 (WWCP_POI3_Tests/Vectors/TS) share, by their fixture. */
const SHARED_FIXTURES = {
    'history-session.json':        'POIHistory/archived-session.chargy',
    'history-witnesses.json':      'POIHistory/trusted-witnesses.json',
    'session-price-ed.json':       'POIPrices/session-with-price.chargy',
    'session-price-pqc.json':      'POIPrices/pqc-price.chargy',
    'session-price-decimal.json':  'POIPrices/decimal-price.chargy',
    'price-publication.json':      'POIPublication/vectors.json',
    'trust-transitions.json':      'POITrustTransitions/vectors.json',
};

const chargyFiles = () => walk(CHARGY_DIR).map(path => relative(CHARGY_DIR, path).split(sep).join('/'));
const readChargy  = (file) => readFileSync(join(CHARGY_DIR, file), 'utf8');

/** The JSON-LD context of a document of an extension, as WWCP_POI3 names it. */
const verifierContext = (file, context) => quoted(`${VERIFIER}/${file}`, `"${context}"`, `the JSON-LD context ${context}`) && context;

const EXTENSION_CONTEXTS = {
    trustTransition:           verifierContext('TrustTransition.cs',       'https://open.charging.cloud/contexts/wwcp/trustTransition/v1'),
    sessionPriceAgreement:     verifierContext('SessionPriceAgreement.cs', 'https://open.charging.cloud/contexts/wwcp/sessionPriceAgreement/v1'),
    pricePublicationReceipt:   verifierContext('PricePublication.cs',      'https://open.charging.cloud/contexts/wwcp/pricePublicationReceipt/v1'),
    witnessPublicationPolicy:  verifierContext('PricePublication.cs',      'https://open.charging.cloud/contexts/wwcp/witnessPublicationPolicy/v1'),
    sessionPriceEvidence:      verifierContext('SessionPriceEvidence.cs',  'https://open.charging.cloud/contexts/wwcp/sessionPriceEvidence/v1'),
    historicalMeterEvidence:   verifierContext('HistoricalMeterEvidence.cs', 'https://open.charging.cloud/contexts/wwcp/historicalMeterEvidence/v1'),
};

/** A document of the run, read with its numbers as written, and every JSON document it holds as a string, read so too. */
function chargyDocument(file) {
    const embedded = (value) => {
        if (typeof value === 'string' && value.startsWith('{') && value.endsWith('}')) {
            try { return embedded(parseRaw(value)); } catch { return value; }
        }
        if (Array.isArray(value))
            return value.map(embedded);
        if (value !== null && typeof value === 'object' && value[RAW] === undefined)
            return Object.fromEntries(Object.entries(value).map(([ key, item ]) => [ key, embedded(item) ]));
        return value;
    };
    return embedded(parseRaw(readChargy(file)));
}

/** The root of a tree of RFC 9162 of a leaf, its index, the size of the tree and the audit path (2.1.3.2), or undefined. */
function rootOfInclusion(hash, leaf, index, size, path) {
    let fn = index, sn = size - 1, r = hash(Buffer.concat([ Buffer.of(0), leaf ]));
    for (const p of path.map(hex => Buffer.from(hex, 'hex'))) {
        if (sn === 0)
            return undefined;
        if ((fn & 1) === 1 || fn === sn) {
            r = hash(Buffer.concat([ Buffer.of(1), p, r ]));
            while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
        }
        else
            r = hash(Buffer.concat([ Buffer.of(1), r, p ]));
        fn >>= 1; sn >>= 1;
    }
    return sn === 0 ? r.toString('hex') : undefined;
}

/**
 * The root of the effective tree a proof of a station gives (8.2, 8.4): every child array as the proof gives it -
 * completely, as the root and size of its tree, or as the leaves it reveals with their audit paths, which must lead
 * to one root -, bottom-up.
 */
function rootOfProof(roamingNetwork) {
    const hash     = hashOf('sha256');
    const skeleton = (entity, parent) => {
        const result = { ...entity };
        for (const array of childArrays()[parent] ?? []) {
            const children = entity[array];
            if (children === undefined || (!Array.isArray(children) && children['@leaves'] === undefined))
                continue;
            if (Array.isArray(children)) {
                result[array] = { '@merkleRoot': mth(hash, children.map(child => utf8(canonical(skeleton(child, CHILD_PARENTS[array]))))).toString('hex'), '@size': children.length };
                continue;
            }
            const size  = numberOf(children['@size']);
            const roots = new Set(children['@leaves'].map(leaf => rootOfInclusion(hash, utf8(canonical(skeleton(leaf['@entity'], CHILD_PARENTS[array]))), numberOf(leaf['@index']), size, leaf['@auditPath'])));
            if (roots.size !== 1 || roots.has(undefined))
                return undefined;
            result[array] = { '@merkleRoot': [ ...roots ][0], '@size': size };
        }
        return result;
    };
    return mth(hash, [ utf8(canonical(skeleton(roamingNetwork, 'roaming network'))) ]).toString('hex');
}

/** The holders of a trust anchor of its QR code: one array of key @ids each, in their order (TrustTransition.PolicyIdOf). */
function policyOfQRCode(text) {
    const map  = decodeCbor(fromBase45(text.slice('WWCP/TA-2:'.length)));
    const hex  = (key) => Buffer.from(key).toString('hex');
    return { network: map['@id'], holders: map.keys.map(key => Array.isArray(key) ? key.map(hex) : [ hex(key) ]), minConsensus: map.minConsensus, urls: map.urls };
}

/**
 * What of the run does not hold, by design: the counterexamples its READMEs name, whose signature, inclusion or digest
 * is broken - and nothing else. Changed and signed again, the others are broken only where a verifier must find it.
 */
const CHARGY_BROKEN = [
    // POISession: "Container key differs", "End reading changed without signing again".
    'POISession/container-key-conflict.chargy: the ocmfBegin signed with the key of the container',
    'POISession/container-key-conflict.chargy: the ocmfEnd signed with the key of the container',
    'POISession/tampered-end-reading.chargy: the ocmfEnd signed with the key of the container',
    // POIHistory: "the container's single key conflicts with the second key", "Modified commit leaf".
    'POIHistory/key-rotation.chargy: the ocmfEnd signed with the key of the container',
    'POIHistory/tampered-checkpoint.chargy: commit inclusion',
    // POIPrices: "Invalid CPO price signature", "Inclusion's embedded price signature is invalid", "a different
    // original-start digest".
    'POIPrices/invalid-signature.chargy: the signature of a priceStatement',
    'POIPrices/tampered-publication.chargy: the signature of a priceStatement',
    'POIPrices/wrong-session.chargy: start document digest',
    // POIPublication, and its variants in vectors.json: a receipt of another statement, of another signed statement, of
    // another tariff; its source URL changed and not signed again - also of private-source, which therefore is refused
    // for its signature as well.
    'POIPublication/wrong-price.chargy: receipt names a statement',
    'POIPublication/wrong-signed-price.chargy: receipt statement SHA-256',
    'POIPublication/wrong-tariff.chargy: receipt tariff SHA-256',
    'POIPublication/tampered-receipt.chargy: the signature of a pricePublicationReceipt',
    'POIPublication/private-source.chargy: the signature of a pricePublicationReceipt',
    'POIPublication/vectors.json: receipt names a statement',
    'POIPublication/vectors.json: receipt statement SHA-256',
    'POIPublication/vectors.json: receipt tariff SHA-256',
    'POIPublication/vectors.json: the signature of a pricePublicationReceipt',
    'POIPublication/vectors.json: the signature of a pricePublicationReceipt',
    // POITrustTransitions: "an invalid target operational certificate", also in vectors.json; the target URL tampered
    // after both quorums signed.
    'POITrustTransitions/invalid-target-certificate.json: the signature of a certificate',
    'POITrustTransitions/vectors.json: the signature of a certificate',
    'POITrustTransitions/tampered-target-url.json: the signature of a trust transition (old)',
    'POITrustTransitions/tampered-target-url.json: the signature of a trust transition (old)',
    'POITrustTransitions/tampered-target-url.json: the signature of a trust transition (new)',
    'POITrustTransitions/tampered-target-url.json: the signature of a trust transition (new)',
];

/** What the run must hold at least once each, so that an anchor that checks nothing is noticed. */
const CHARGY_HOLDS = [
    ...[ 'key statement', 'certificate', 'attestation', 'checkpoint (roamingNetworkOperator)', 'checkpoint (witness)', 'priceStatement',
         'sessionPriceAgreement', 'pricePublicationReceipt', 'trust transition (old)', 'trust transition (new)' ].map(what => `the signature of a ${what}`),
    'checkpoint id', 'commit id', 'proof root', 'commit inclusion', 'price statement inclusion', 'meter key id', 'the ocmfBegin signed with the key of the container',
    'the ocmfEnd signed with the key of the container', 'start document digest', 'agreement names a statement', 'receipt names a statement',
    'receipt statement SHA-256', 'receipt tariff SHA-256', 'policy id', 'key statement digest', 'provenance', 'shared copy',
];

function anchorTheChargyRun() {

    // The inputs and digests of the extensions, as WWCP_POI3 calculates them: an agreement and a receipt sign what they
    // name but their value, a transition its content with the side, the algorithm and the key of a signature; a receipt
    // binds the canonical JSON of the statement as signed and of the tariff; a policy its URLs as absolute URIs, without
    // trailing slashes, in their ordinal order.
    quoted(`${VERIFIER}/SessionPriceAgreement.cs`, 'The signature input: the canonical JSON of what it names, but its value.', 'the signature input of an agreement');
    quoted(`${VERIFIER}/PricePublication.cs`,      'The signature input: the canonical JSON of what it names, but its value.', 'the signature input of a receipt');
    quoted(`${VERIFIER}/PricePublication.cs`,      'JSON of the complete original price statement, its signature included, and of the complete tariff selected, its', 'what a receipt binds');
    quoted(`${VERIFIER}/TrustTransition.cs`,       'signed["side"]       = Side;', 'that a signature of a transition signs its side');
    quoted(`${VERIFIER}/TrustTransition.cs`,       "new Uri(url.ToString()).AbsoluteUri.TrimEnd('/')).", 'the URLs of the policy identity');
    quoted(`${VERIFIER}/TrustTransition.cs`,       'Order(StringComparer.Ordinal)', 'the order of the URLs of the policy identity');

    // What holds, by kind; what does not, as `file: what`.
    const verified = {}, broken = [];
    const holds    = (what) => verified[what] = (verified[what] ?? 0) + 1;

    const files = chargyFiles().filter(file => file.endsWith('.json') || file.endsWith('.chargy'));
    const documents = files.map(file => ({ file, json: chargyDocument(file) }));

    // Keys: every COSE key the run names, by its @id; a key that is no COSE key (a meter's SubjectPublicKeyInfo) apart.
    const keys = new Map(), spkis = new Map();
    const collect = (value) => {
        if (Array.isArray(value))
            value.forEach(collect);
        else if (value !== null && typeof value === 'object' && value[RAW] === undefined) {
            if (typeof value['@id'] === 'string' && typeof value.key === 'string') {
                const first = Buffer.from(value.key, 'base64')[0];
                if (first >> 5 === 5) keys.set(value['@id'], value.key);
                else                  spkis.set(value['@id'], value.key);
            }
            Object.values(value).forEach(collect);
        }
    };
    documents.forEach(({ json }) => collect(json));

    const check = (file, what, { algorithm, keyId, value }, input) => {
        const result = verifiesWith(algorithm, keys.get(keyId) ?? fail(`anchor: ${file}: no key ${keyId} of a ${what}`), input, value);
        if      (result === true)  holds(`the signature of a ${what}`);
        else if (result === false) broken.push(`${file}: the signature of a ${what}`);
        else                       fail(`anchor: ${file}: node:crypto does not verify ${algorithm}, the signature of a ${what}`);
    };

    const visit = (file, value, parentKey) => {
        if (Array.isArray(value)) {
            value.forEach(item => visit(file, item, parentKey));
            return;
        }
        if (value === null || typeof value !== 'object' || value[RAW] !== undefined)
            return;
        const context = value['@context'];
        if (context === CONTEXTS.checkpoint) {
            for (const signature of value.signatures ?? [])
                check(file, `checkpoint (${signature.role})`, signature, roleSignatureInput(CONTEXTS.checkpointSignature, signature, 'checkpoint', checkpointAsSigned(value)));
        }
        else if (context === CONTEXTS.commit) {
            for (const signature of value.signatures ?? [])
                check(file, 'commit', signature, roleSignatureInput(CONTEXTS.commitSignature, signature, 'commit', commitAsSigned(value)));
        }
        else if (context === CONTEXTS.priceStatement || context === EXTENSION_CONTEXTS.sessionPriceAgreement || context === EXTENSION_CONTEXTS.pricePublicationReceipt)
            check(file, context.split('/').slice(-2)[0], value, canonical(without(value, 'value')));
        else if (context === EXTENSION_CONTEXTS.trustTransition) {
            for (const signature of value.signatures ?? [])
                check(file, `trust transition (${signature.side})`, signature, canonical({ ...without(value, 'signatures'), side: signature.side, algorithm: signature.algorithm, keyId: signature.keyId }));
        }
        if (value.signingKey !== undefined && value.roamingNetworkOperatorId !== undefined && typeof value.value === 'string')
            check(file, 'certificate', value, certificateSignatureInput(value));
        if (Array.isArray(value.identityKeys) && Array.isArray(value.signatures) && value.roamingNetworkOperatorId !== undefined)
            for (const signature of value.signatures)
                check(file, 'key statement', signature, keyStatementSignatureInput(value, signature));
        if (parentKey === 'attestations')
            check(file, 'attestation', value, attestationSignatureInput(value));
        for (const [ key, item ] of Object.entries(value))
            visit(file, item, key);
    };
    documents.forEach(({ file, json }) => visit(file, json, undefined));

    // Everything else, per document: found by its kind.
    const expect = (file, what, actual, expected) => actual === expected ? holds(what) : broken.push(`${file}: ${what}`);

    const checkpoints = new Map();
    for (const { file, json } of documents)
        for (const checkpoint of all(json, value => value['@context'] === CONTEXTS.checkpoint)) {
            expect(file, 'checkpoint id', checkpointIdOf(checkpoint, 'sha256'), checkpoint['@id']);
            checkpoints.set(checkpoint['@id'], checkpoint);
        }

    const statementDigest = (statement) => sha256(utf8(canonical({ '@context': CONTEXTS.priceStatement, ...without(statement, 'value') })));

    for (const { file, json } of documents) {

        for (const commit of all(json, value => value['@context'] === CONTEXTS.commit))
            expect(file, 'commit id', commitIdOf(commit, identificationHashOf(commit['@id'])), commit['@id']);

        for (const proof of all(json, value => value['@context'] === CONTEXT + 'proof/v1')) {
            const root = rootOfProof(proof.roamingNetwork);
            for (const attestation of proof.attestations ?? [])
                expect(file, 'proof root', root, attestation.eTag?.[3]);
        }

        for (const proof of all(json, value => value['@context'] === CONTEXT + 'checkpointProof/v1')) {
            const checkpoint = checkpoints.get(proof.checkpointId);
            expect(file, 'commit inclusion', rootOfInclusion(hashOf('sha256'), commitLeafOf({ '@id': proof.leaf.commitId, eTags: proof.leaf.eTags, revision: proof.leaf.revision }), numberOf(proof['@index']), numberOf(proof['@size']), proof['@auditPath']), checkpoint?.commits?.['@merkleRoot']);
        }

        for (const proof of all(json, value => value['@context'] === CONTEXT + 'priceStatementProof/v1')) {
            const checkpoint = checkpoints.get(proof.checkpointId);
            expect(file, 'price statement inclusion', rootOfInclusion(hashOf('sha256'), Buffer.from(statementDigest(proof.priceStatement), 'hex'), numberOf(proof['@index']), numberOf(proof['@size']), proof['@auditPath']), checkpoint?.priceStatements?.['@merkleRoot']);
        }

        for (const session of all(json, value => typeof value.ocmfBegin === 'string')) {
            const spki = createPublicKey({ key: Buffer.from(session.publicKey, 'base64'), format: 'der', type: 'spki' });
            for (const which of [ 'ocmfBegin', 'ocmfEnd' ]) {
                const [ , payload, signature ] = /^OCMF\|(.*)\|(\{[^|]*\})$/s.exec(session[which]) ?? fail(`${file}: ${which} is no OCMF`);
                const { SA, SD } = JSON.parse(signature);
                if (SA !== 'ECDSA-secp256r1-SHA256')
                    fail(`anchor: ${file}: ${which} signed with ${SA}`);
                expect(file, `the ${which} signed with the key of the container`, verify('sha256', utf8(payload), { key: spki, dsaEncoding: 'der' }, Buffer.from(SD, 'hex')), true);
            }
            const agreement = session.poiEvidence?.priceEvidence?.agreement;
            if (agreement !== undefined)
                expect(file, 'start document digest', sha256(utf8(session.ocmfBegin)), agreement.startDocumentSHA256);
        }

        for (const evidence of all(json, value => value['@context'] === EXTENSION_CONTEXTS.sessionPriceEvidence)) {
            const digests = new Map((evidence.priceStatements ?? []).map(statement => [ statementDigest(statement), statement ]));
            if (evidence.agreement !== undefined)
                expect(file, 'agreement names a statement', digests.has(evidence.agreement.priceStatementDigest), true);
            for (const receipt of evidence.publicationReceipts ?? []) {
                const statement = digests.get(receipt.priceStatementDigest);
                expect(file, 'receipt names a statement', statement !== undefined, true);
                if (statement !== undefined)
                    expect(file, 'receipt statement SHA-256', sha256(utf8(canonical(statement))), receipt.priceStatementSHA256);
                const tariffs = all(evidence.chargingStationProof, value => value['@id'] === statement?.priceStatus?.chargingTariffId || value['@id'] === evidence.agreement?.chargingTariffId).filter(value => value.currency !== undefined);
                expect(file, 'receipt tariff SHA-256', tariffs.some(tariff => sha256(utf8(canonical(tariff))) === receipt.tariffSHA256), true);
            }
        }

    }

    // The keys of meters, SubjectPublicKeyInfo: each identified by its SHA-256 (sha256-spki).
    for (const [ id, key ] of spkis)
        expect('the run', 'meter key id', sha256(Buffer.from(key, 'base64')), id);

    // Trust transitions: each continues the trust anchor and the key statement of POITrustTransitions/vectors.json.
    const succession = documents.find(({ file }) => file === 'POITrustTransitions/vectors.json').json;
    for (const { file, json } of documents)
        for (const transition of all(json, value => value['@context'] === EXTENSION_CONTEXTS.trustTransition)) {
            expect(file, 'policy id', policyIdOf(succession.anchor), transition.fromPolicyId);
            expect(file, 'key statement digest', keyStatementDigestOf(succession.operator.keyStatement), transition.fromStatementDigest);
        }

    // The hashes of the provenance of each set, and the vector files WWCP_POI.TS and WWCP_POI3 share, byte for byte.
    for (const set of CHARGY_SETS) {
        const provenance = JSON.parse(readChargy(`${set}/provenance.json`));
        for (const [ name, hash ] of Object.entries(provenance.files))
            expect(`${set}/provenance.json`, 'provenance', sha256(readFileSync(join(CHARGY_DIR, set, name))), typeof hash === 'string' ? hash : hash.sha256);
    }
    for (const [ name, fixture ] of Object.entries(SHARED_FIXTURES))
        for (const copy of [ `libs/WWCP_POI.TS/tests/vectors/${name}`, `libs/WWCP_POI/WWCP_POI3_Tests/Vectors/TS/${name}` ])
            expect(copy, 'shared copy', existsSync(join(ROOT, copy)) && readFileSync(join(ROOT, copy)).equals(readFileSync(join(CHARGY_DIR, fixture))), true);

    anchor('what of the run does not hold', JSON.stringify(broken.sort(), null, 1), JSON.stringify([ ...CHARGY_BROKEN ].sort(), null, 1));
    for (const what of CHARGY_HOLDS)
        if (verified[what] === undefined)
            fail(`anchor: nothing of the run checked as ${what}`);

}

/** A document of the run: a file and a JSON pointer into it, read on into a string, which is a JSON document of its own. */
function chargyAt(file, pointer) {
    let value = chargyDocument(file);
    for (const token of pointer === '' ? [] : pointer.slice(1).split('/').map(item => item.replaceAll('~1', '/').replaceAll('~0', '~')))
        value = value?.[Array.isArray(value) ? Number(token) : token] ?? fail(`${file}: the pointer ${pointer} names nothing`);
    return value;
}

/** The identification of a P-256 key of its SubjectPublicKeyInfo as a COSE key (RFC 9679): SHA-256 of {1: 2, -1: 1, -2: x, -3: y}. */
function coseThumbprintOfSPKI(spkiBase64) {
    const spki = Buffer.from(spkiBase64, 'base64');
    if (spki.length !== 91 || spki[26] !== 0x04)
        fail('a meter key that is no uncompressed P-256 SubjectPublicKeyInfo');
    return sha256(Buffer.concat([ Buffer.from('a401022001215820', 'hex'), spki.subarray(27, 59), Buffer.from('225820', 'hex'), spki.subarray(59) ]));
}

// =====================================================================================================================
//  9a. Prices bound to a session, made here: chargy/POIPrices
// =====================================================================================================================
//
// The documents of the prices of a session ChargyWebApp fc513cd made (build-tools/generatePOIPriceExample.mjs, POIPrices),
// made here as it made them, of the same public seeds - the CPO's Ed25519 key 161, the attestation keys 142 and 144, the
// checkpoint keys 42 and 44, the witness 151 -, on POIHistory/archived-session.chargy of the run: every signature
// deterministic, so that the files are generated, not frozen, and drift guarded as the vector files are. Two things are
// not as there: the readings of the meter are signed by a P-256 key of a seed of its own (RFC 6979), not by the published
// test key whose ECDSA signatures differ every time, its key in the container and in the proof of the station with it;
// and two counterexamples show what their README says, which their fixtures no longer do since SPECIFICATION.md says
// otherwise - foreign-tariff a tariff of the pattern {operatorId}*T{suffix}, DE*POI*T2, conditional-price a restriction
// POI defines, maxEnergy. ML-DSA-65 node:crypto signs with randomness: pqc-price stays the one of the run.
//
// Each case is made twice: once with the readings of its fixture and the key of its meter, which must give the fixture
// itself, its JSON as canonical JSON (the anchor); then with the readings signed anew, which is the file written.

const OWN_CHARGY      = 'chargy';
const OWN_CHARGY_DIR  = join(OUT, OWN_CHARGY);

/** JSON with its numbers as written: two spaces, LF, a final newline. */
const serializeRaw = (value) => JSON.stringify(value, (_key, item) => item !== null && typeof item === 'object' && item[RAW] !== undefined ? `\u0000raw:${item[RAW]}\u0000` : item, 2)
                                    .replace(/"\\u0000raw:([^"\\]*)\\u0000"/gu, '$1') + '\n';

/** A signature r || s (Base64) as DER, in upper case hex, as OCMF gives it. */
function derOfRaw(rawBase64) {
    const raw     = Buffer.from(rawBase64, 'base64');
    const integer = (bytes) => {
        let value = bytes;
        while (value.length > 1 && value[0] === 0 && value[1] < 0x80)
            value = value.subarray(1);
        if (value[0] >= 0x80)
            value = Buffer.concat([ Buffer.of(0), value ]);
        return Buffer.concat([ Buffer.of(0x02, value.length), value ]);
    };
    const body = Buffer.concat([ integer(raw.subarray(0, 32)), integer(raw.subarray(32)) ]);
    return Buffer.concat([ Buffer.of(0x30, body.length), body ]).toString('hex').toUpperCase();
}

/** The SubjectPublicKeyInfo of an ES256 key of its COSE key (EC2, crv 1): the uncompressed point, in Base64. */
function spkiOfES256(coseKey) {
    const bytes = Buffer.from(coseKey, 'base64');
    return Buffer.concat([ Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200' + '04', 'hex'), bytes.subarray(8, 40), bytes.subarray(43, 75) ]).toString('base64');
}

/** The price statements of a checkpoint in the order of its tree (12.3, RoamingNetworkPriceStatement.InOrder). */
const statementsInOrder = (statements, digest) => [ ...statements ].sort((left, right) => {
    const ordinal = (a, b) => a < b ? -1 : a > b ? 1 : 0;
    return ordinal(left.entityType, right.entityType) || ordinal(left.entityId, right.entityId) || numberOf(left.sequence) - numberOf(right.sequence) || ordinal(digest(left), digest(right));
});

function ownPriceSessions() {

    const SET         = 'POIPrices';
    const original    = parseRaw(readChargy('POIHistory/archived-session.chargy'));
    const provenance  = JSON.parse(readChargy(`${SET}/provenance.json`));
    const START       = Date.parse(provenance.chargingStarted);
    const iso         = (time) => new Date(time).toISOString();
    const raw         = (text) => ({ [RAW]: text });

    const NETWORK     = original.poiEvidence.roamingNetworkId;
    const EVSE        = original.poiEvidence.EVSEId;
    const CPO         = 'DE*POI';
    const TARIFF      = 'DE*POI*T1';
    const SERIAL      = 'CHARGY-POI-METER-001';
    const base        = original.poiEvidence.historicalEvidence.versions[0];
    const baseProof   = base.chargingStationProof;
    const operatorOf  = base.checkpoints[0].operator;

    const seedByte    = (byte) => Buffer.alloc(32, byte).toString('hex');
    const ed          = (byte) => ed25519(seedByte(byte));
    const digestOf    = (statement) => sha256(utf8(canonical({ '@context': CONTEXTS.priceStatement, ...without(statement, 'value') })));

    // The CPO's signing key for price statements, Ed25519 of the seed 161, as the generator of ChargyWebApp names it.
    const cpoKey = (usages = [ 'priceStatements' ]) => {
        const key     = ed(161);
        const coseKey = coseKeyOf(key.publicKey);
        return { algorithm: 'Ed25519', sign: key.sign,
                 json: { '@id': sha256(Buffer.from(coseKey, 'base64')), key: coseKey, usages, notBefore: '2026-01-01T00:00:00.000Z', notAfter: '2030-01-01T00:00:00.000Z' } };
    };

    // The meter: of a seed of its own, its readings signed with the nonces of RFC 6979.
    const meter     = es256(seedOf('CHARGY-POI-METER-001, the meter of the prices of a session'));
    const meterSPKI = spkiOfES256(meter.coseKey);

    /** A reading of the meter, as the generator of ChargyWebApp signs it again: IT, ID and TT set, the rate given. */
    const reading = (ocmf, rate) => {
        const payload = JSON.parse(ocmf.substring(ocmf.indexOf('|') + 1, ocmf.lastIndexOf('|')));
        payload.IT = 'NONE';
        payload.ID = 'ADHOC-PRICE-DEMO';
        payload.TT = `001;EUR;0;${rate};0;0`;
        const text = JSON.stringify(payload);
        return `OCMF|${text}|${JSON.stringify({ SA: 'ECDSA-secp256r1-SHA256', SE: 'hex', SD: derOfRaw(meter.sign(text)) })}`;
    };

    const price = (key, changes = {}) => {
        const value = { '@context': CONTEXTS.priceStatement, roamingNetworkId: NETWORK, entityType: 'EVSE', entityId: EVSE,
                        priceStatus: { prices: [ { chargingTariffId: TARIFF, elements: [ { priceComponents: [ { type: 'ENERGY', price: raw('0.35'), stepSize: 1 } ] } ] } ] },
                        signedAt: iso(START - 300_000), validFrom: iso(START - 60_000), validUntil: iso(START + 300_000), sequence: 0, role: 'chargingStationOperator', signer: CPO,
                        algorithm: key.algorithm, keyId: key.json['@id'], ...changes, value: 'placeholder' };
        return { ...value, value: key.sign(canonical(without(value, 'value'))) };
    };
    const reprice = (statement, key, changes) => price(key, { ...statement, ...changes });

    const agreementOf = (key, statement, begin, changes = {}) => {
        const value = { '@context': EXTENSION_CONTEXTS.sessionPriceAgreement, roamingNetworkId: NETWORK, EVSEId: EVSE, meterSerialNumber: SERIAL, chargingStarted: iso(START),
                        startDocumentSHA256: sha256(utf8(begin)), chargingMode: 'adhoc', chargingTariffId: TARIFF, priceStatementDigest: digestOf(statement),
                        priceBinding: 'fixed-at-start', pricingProfile: 'chargy-gross-rates/v1', role: 'chargingStationOperator', signer: CPO, signedAt: iso(START + 60_000),
                        algorithm: key.algorithm, keyId: key.json['@id'], ...changes };
        return { ...value, value: key.sign(canonical(value)) };
    };

    /** The proof of the station with the key of the CPO, its commit, attestations and checkpoint, naming the statements. */
    const publication = (key, statements, meterKey) => {

        const proof    = copyOf(baseProof);
        proof.roamingNetwork.chargingStationOperators[0].signingKeys = [ key.json ];
        if (meterKey !== undefined)
            for (const energyMeter of all(proof.roamingNetwork, value => value.serialNumber === SERIAL))
                energyMeter.publicKeys = [ meterKey ];

        const eTag     = [ 'effectiveTree', 'sha256', 'hex', rootOfProof(proof.roamingNetwork) ];
        const eTags    = [ [ 'json', 'sha256', 'hex', sha256(utf8(canonical(proof.roamingNetwork))) ], [ 'cbor', 'sha256', 'hex', createHash('sha256').update(cborOf(proof.roamingNetwork)).digest('hex') ], eTag ];
        const content  = { '@context': CONTEXTS.commit, roamingNetworkId: NETWORK, revision: 0, eTags };
        const commit   = { '@id': commitIdOf(content, 'sha256'), ...content };
        proof.commitId = commit['@id'];
        proof.revision = 0;
        proof.attestations = baseProof.attestations.map((item, index) => {
            const value = { ...item, commitId: commit['@id'], revision: 0, eTag, value: 'placeholder' };
            return { ...value, value: ed(index === 0 ? 142 : 144).sign(attestationSignatureInput(value)) };
        });

        const ordered  = statementsInOrder(statements, digestOf);
        const at       = iso(START + 86_400_000);
        const body     = { '@context': CONTEXTS.checkpoint, roamingNetworkId: NETWORK, epoch: 1, sequence: 0, commitId: commit['@id'], revision: 0, eTags,
                           commits:         { '@merkleRoot': mth(hashOf('sha256'), [ commitLeafOf(commit) ]).toString('hex'), '@size': 1 },
                           priceStatements: { '@merkleRoot': mth(hashOf('sha256'), ordered.map(statement => Buffer.from(digestOf(statement), 'hex'))).toString('hex'), '@size': ordered.length },
                           createdAt: at };
        const identified = { '@id': checkpointIdOf(body, 'sha256'), ...body };
        const signatures = [ 42, 44, 151 ].map((seed, index) => {
            const signature = { role: index < 2 ? 'roamingNetworkOperator' : 'witness', signer: index < 2 ? operatorOf['@id'] : 'CHARGY-DEMO-WITNESS', signedAt: at, algorithm: 'Ed25519',
                                keyId: index < 2 ? operatorOf.signingKeyCertificates[index].signingKey['@id'] : base.checkpoints[0].checkpoint.signatures[2].keyId };
            return { ...signature, value: ed(seed).sign(roleSignatureInput(CONTEXTS.checkpointSignature, signature, 'checkpoint', checkpointAsSigned(identified))) };
        });
        const checkpoint  = { ...identified, signatures };
        const commitProof = { '@context': CONTEXT + 'checkpointProof/v1', checkpointId: checkpoint['@id'], leaf: { commitId: commit['@id'], eTags, revision: 0 },
                              '@index': 0, '@size': 1, '@auditPath': [] };
        return { proof, commitProof, checkpoints: [ { checkpoint, operator: copyOf(operatorOf) } ] };

    };

    /** A session with the price evidence of a case, its readings given (the anchor) or signed anew with the rate given. */
    const made = ({ usages, statements: editStatements, agreement: editAgreement, missingAgreement = false, rate = '35', missingProof = false, tamperedProof = false, fork = false } = {},
                  readings) => {

        const key        = cpoKey(usages);
        const begin      = readings?.begin ?? reading(original.ocmfBegin, rate);
        const end        = readings?.end   ?? reading(original.ocmfEnd,   rate);
        const meterKey   = readings === undefined ? { '@id': sha256(Buffer.from(meterSPKI, 'base64')), key: meterSPKI } : undefined;
        const statements = editStatements === undefined ? [ price(key) ] : editStatements([ price(key) ], key);
        const published  = publication(key, statements, meterKey);
        const selected   = statements[0];
        const checkpoint = published.checkpoints[0].checkpoint;

        const priceProofs = statements.length === 1 ? [ { '@context': CONTEXT + 'priceStatementProof/v1', checkpointId: checkpoint['@id'], priceStatement: selected, '@index': 0, '@size': 1, '@auditPath': [] } ] : [];
        if (tamperedProof)
            priceProofs[0].priceStatement = { ...selected, value: selected.value.slice(0, -4) + 'AAAA' };

        const evidence = { '@context': EXTENSION_CONTEXTS.sessionPriceEvidence, EVSEId: EVSE, chargingStationProof: published.proof, priceStatements: statements,
                           ...(missingAgreement ? {} : { agreement: agreementOf(key, selected, begin, editAgreement) }),
                           ...(missingProof     ? {} : { priceStatementProofs: priceProofs, checkpoints: published.checkpoints }) };
        const history  = { ...copyOf(original.poiEvidence.historicalEvidence), versions: [ { chargingStationProof: published.proof, commitProof: published.commitProof, checkpoints: published.checkpoints } ] };

        if (fork) {
            const bare      = without(checkpoint, '@id', 'signatures', 'priceStatements');
            const forked    = { '@id': checkpointIdOf(bare, 'sha256'), ...bare };
            const signed    = checkpoint.signatures.filter(signature => signature.role === 'roamingNetworkOperator')
                                                    .map((signature, index) => ({ ...signature, value: ed(index === 0 ? 42 : 44).sign(roleSignatureInput(CONTEXTS.checkpointSignature, signature, 'checkpoint', checkpointAsSigned(forked))) }));
            history.versions[0].commitProof = { ...published.commitProof, checkpointId: forked['@id'] };
            history.versions[0].checkpoints = [ { checkpoint: { ...forked, signatures: signed }, operator: copyOf(operatorOf) } ];
        }

        return { ...copyOf(original), ...(meterKey === undefined ? {} : { publicKey: meterSPKI }), ocmfBegin: begin, ocmfEnd: end,
                 poiEvidence: { ...copyOf(original.poiEvidence), historicalEvidence: history, priceEvidence: evidence } };

    };

    const status   = (statement, edit) => { const priceStatus = copyOf(statement.priceStatus); edit(priceStatus.prices[0]); return { priceStatus }; };
    const element  = (prices) => prices.elements[0];

    // The cases of the generator of ChargyWebApp, by their file; `ownCase` where this one makes it otherwise.
    const CASES = {
        'session-with-price.chargy':    {},
        'missing-agreement.chargy':     { missingAgreement: true },
        'empty-prices.chargy':          { missingAgreement: true, missingProof: true, statements: () => [] },
        'decimal-price.chargy':         { statements: (items, key) => [ reprice(items[0], key, status(items[0], prices => element(prices).priceComponents[0].price = raw('0.3500'))) ] },
        'missing-publication.chargy':   { missingProof: true },
        'invalid-signature.chargy':     { statements: items => [ { ...items[0], value: items[0].value.slice(0, -4) + 'AAAA' } ], missingAgreement: true, missingProof: true },
        'wrong-evse.chargy':            { statements: (items, key) => [ reprice(items[0], key, { entityId: 'DE*POI*E9*1' }) ], missingProof: true },
        'expired-price.chargy':         { statements: (items, key) => [ reprice(items[0], key, { validUntil: iso(START - 1) }) ] },
        'foreign-tariff.chargy':        { statements: (items, key) => [ reprice(items[0], key, status(items[0], prices => prices.chargingTariffId = 'DE*POI*FOREIGN')) ],
                                          ownCase:    (items, key) => [ reprice(items[0], key, status(items[0], prices => prices.chargingTariffId = 'DE*POI*T2')) ] },
        'unauthorized-key.chargy':      { usages: [ 'infrastructure' ] },
        'wrong-session.chargy':         { agreement: { startDocumentSHA256: 'ff'.repeat(32) } },
        'contract-mode.chargy':         { agreement: { chargingMode: 'contract' } },
        'variable-binding.chargy':      { agreement: { priceBinding: 'variable' } },
        'signed-rate-conflict.chargy':  { rate: '65' },
        'tampered-publication.chargy':  { tamperedProof: true },
        'checkpoint-fork.chargy':       { fork: true },
        'split-price-chain.chargy':     { missingProof: true, statements: (items, key) => [ ...items, reprice(items[0], key, status(items[0], prices => element(prices).priceComponents[0].price = raw('0.45'))) ] },
        'broken-price-chain.chargy':    { missingProof: true, statements: (items, key) => [ ...items, reprice(items[0], key, { sequence: 1, previous: 'ff'.repeat(32), validFrom: iso(START - 1000) }) ] },
        'ambiguous-offers.chargy':      { missingProof: true, missingAgreement: true, statements: (items, key) => [ ...items, reprice(items[0], key, { entityType: 'ChargingPool', entityId: 'DE*POI*P1' }) ] },
        'conditional-price.chargy':     { statements: (items, key) => [ reprice(items[0], key, status(items[0], prices => element(prices).restrictions = { max_kwh: raw('5') })) ],
                                          ownCase:    (items, key) => [ reprice(items[0], key, status(items[0], prices => element(prices).restrictions = { maxEnergy: raw('5') })) ] },
    };

    if (Object.keys(CASES).length + 1 !== Object.keys(provenance.files).length || !Object.keys(provenance.files).includes('pqc-price.chargy'))
        fail(`chargy/${SET}: the cases are not those of ${SET} of the run, pqc-price.chargy aside`);

    const documents = {};
    for (const [ file, { ownCase, ...options } ] of Object.entries(CASES)) {
        const fixture = parseRaw(readChargy(`${SET}/${file}`));
        const remade  = canonical(made(options, { begin: fixture.ocmfBegin, end: fixture.ocmfEnd }));
        if (remade !== canonical(fixture))
            fail(`anchor: chargy/${SET}/${file} is not made as the generator of ChargyWebApp made it, of its readings: ${differences(parseRaw(remade), parseRaw(canonical(fixture))).slice(0, 5).join('; ')}`);
        const own = made(ownCase === undefined ? options : { ...options, statements: ownCase });
        for (const which of [ 'ocmfBegin', 'ocmfEnd' ]) {
            const [ , payload, signature ] = /^OCMF\|(.*)\|(\{[^|]*\})$/su.exec(own[which]);
            if (!verify('sha256', utf8(payload), { key: createPublicKey({ key: Buffer.from(meterSPKI, 'base64'), format: 'der', type: 'spki' }), dsaEncoding: 'der' }, Buffer.from(JSON.parse(signature).SD, 'hex')))
                fail(`chargy/${SET}/${file}: node:crypto does not verify its ${which} with the key of its meter`);
        }
        documents[`${SET}/${file}`] = own;
    }

    return documents;

}

/** The documents made here (chargy/), by their file. */
let OWN_DOCUMENTS;

/** What the cases made here show, where it is not what the README of the run says. */
const OWN_SAYS = {
    'foreign-tariff.chargy':    'Genuine price naming a tariff outside this EVSE\'s references: DE*POI*T2, of the pattern {operatorId}*T{suffix}',
    'conditional-price.chargy': 'Conditional tariff elements are explicitly unsupported: an element restricted by maxEnergy',
};

/** The files of chargy/ as text: each document, and the README and provenance of each set. */
function ownChargyFiles() {

    const files = {};
    for (const [ file, document ] of Object.entries(OWN_DOCUMENTS))
        files[`${OWN_CHARGY}/${file}`] = serializeRaw(document);

    const SET  = 'POIPrices';
    const run  = JSON.parse(readChargy(`${SET}/provenance.json`));
    const said = (name) => OWN_SAYS[name] ?? (readChargy(`${SET}/README.md`).match(new RegExp(`^\\| \`${name.replaceAll('.', '\\.')}\` \\| (.+?) \\|$`, 'm')) ?? fail(`${SET}/README.md: no row of ${name}`))[1];
    const made = Object.keys(files).filter(name => name.startsWith(`${OWN_CHARGY}/${SET}/`)).map(name => name.slice(`${OWN_CHARGY}/${SET}/`.length)).sort();

    files[`${OWN_CHARGY}/${SET}/provenance.json`] = JSON.stringify({
        generator:        'WWCPPOIConformanceTests: tools/generate-test-vectors.mjs, section 9a',
        madeAs:           `build-tools/generatePOIPriceExample.mjs of ChargyWebApp ${CHARGY.split('-').pop()} made ${SET}, each case anchored on its fixture`,
        evaluatedAt:      run.evaluatedAt,
        chargingStarted:  run.chargingStarted,
        checkpointAt:     run.checkpointAt,
        evseId:           run.evseId,
        keySeeds:         `PUBLIC TEST KEYS ONLY: CPO Ed25519=161; RNO identities 41/43, historical keys 142/144, checkpoint 42/44, witness 151; the meter ES256 of the seed of "CHARGY-POI-METER-001, the meter of the prices of a session" (RFC 6979)`,
        profile:          run.profile,
        files:            Object.fromEntries(made.map(name => [ name, sha256(utf8(files[`${OWN_CHARGY}/${SET}/${name}`])) ])),
    }, null, 2) + '\n';

    files[`${OWN_CHARGY}/${SET}/README.md`] = [
        '# Session price evidence, made by WWCPPOIConformanceTests',
        '',
        'GENERATED by `tools/generate-test-vectors.mjs` (section 9a) - never edit, regenerate. Public test material only.',
        '',
        `The cases of \`${SET}\` of ChargyWebApp \`${CHARGY.split('-').pop()}\` (\`build-tools/generatePOIPriceExample.mjs\`), made as it made`,
        'them, of the same public seeds, on `POIHistory/archived-session.chargy` of its fixtures - but every signature',
        'deterministic: the readings of the meter are signed with a P-256 key of a seed of its own, with the nonces of RFC 6979,',
        'not with the published test key, whose ECDSA signatures differ every time. Each case is anchored first: made with the',
        'readings of its fixture, it is that fixture. `pqc-price.chargy` is not made here: node:crypto signs ML-DSA-65 with',
        'randomness. What both WWCP_POI3 and WWCP_POI.TS give for each is in `poi-verifier.json` (`sessionPrice-*`).',
        '',
        `The fixed evaluation clock is **${run.evaluatedAt.replace('.000Z', 'Z')}**; charging starts at ${run.chargingStarted.replace('.000Z', 'Z')}.`,
        '',
        '| File | Expected scoped result |',
        '| --- | --- |',
        ...made.map(name => `| \`${name}\` | ${said(name)} |`),
        '',
    ].join('\n');

    return files;

}

/** A document made here: a file and a JSON pointer into it. */
function ownAt(file, pointer) {
    let value = OWN_DOCUMENTS[file] ?? fail(`chargy/${file}: no document made here`);
    for (const token of pointer === '' ? [] : pointer.slice(1).split('/').map(item => item.replaceAll('~1', '/').replaceAll('~0', '~')))
        value = value?.[Array.isArray(value) ? Number(token) : token] ?? fail(`chargy/${file}: the pointer ${pointer} names nothing`);
    return value;
}

function verifierVectors() {

    anchorTheChargyRun();
    OWN_DOCUMENTS = ownPriceSessions();

    const TS_README  = 'libs/WWCP_POI.TS/README.md';
    const POI_README = 'libs/WWCP_POI/README.md';
    const vectors    = [];
    const accept     = (vector) => vectors.push({ expected: 'accepted', ...vector });
    const frozenRef  = (file, pointer = '') => ({ file, pointer });
    const frozenAt   = (file, pointer) => chargyAt(file, pointer);
    // A document made here (chargy/) where one of the file is made here, else the one of the run.
    const ref        = (file, pointer = '') => OWN_DOCUMENTS[file] === undefined ? frozenRef(file, pointer) : { documents: OWN_CHARGY, file, pointer };
    const at         = (file, pointer) => OWN_DOCUMENTS[file] === undefined ? frozenAt(file, pointer) : ownAt(file, pointer);
    const provenance = (set) => JSON.parse(readChargy(`${set}/provenance.json`));

    // What both READMEs say of the extensions: experimental, made in WWCP_POI3 as WWCP_POI.TS verifies them.
    quoted(TS_README,  'The versioned historical\nand session-price evidence, compact trust delegation and publication-receipt profiles remain experimental', 'that the extensions are experimental');
    quoted(POI_README, '**Verifier extensions of WWCP_POI.TS 0.2.0 (experimental):**', 'that WWCP_POI3 has the extensions of WWCP_POI.TS 0.2.0');
    const basis = (section, file) => `${TS_README}, ${quoted(TS_README, `### ${section}`, `the section ${section}`).slice(4)} (experimental); WWCP_POI3/Verifier/${file}`;

    /** What a README of the run says a counterexample is: its row of the table. */
    const said = (set, name) => (readChargy(`${set}/README.md`).match(new RegExp(`^\\| \`${name.replaceAll('.', '\\.')}\` \\| (.+?) \\|$`, 'm')) ?? fail(`${set}/README.md: no row of ${name}`))[1];

    // The local trust of a verification: the trust anchor and key statement a fixture bootstraps with, every identity
    // key of the anchor trusted.
    const bootstrapOf = (file, at, context = 'current', keyStatement = '/poiEvidence/bootstrap/keyStatement/keyStatement', refOf = ref) =>
        ({ anchor: refOf(file, '/poiEvidence/bootstrap/trustAnchor'), keyStatement: refOf(file, keyStatement), at, context });

    const EVSE    = provenance('POISession').evseId;
    const SERIAL  = provenance('POISession').meterSerial;

    // ---- The key of the meter of an EVSE, of a current station proof (VerifiedMeterKeyBinding): the one key the proof
    //      gives its meter, of the serial number asked for, identified by the SHA-256 of its SubjectPublicKeyInfo and,
    //      canonically, by its COSE thumbprint - both calculated here.
    {
        const session  = provenance('POISession');
        const meterKey = (id, file, description, request = {}) => {
            const proof = at(file, '/poiEvidence/chargingStationProof');
            const keys  = all(proof, value => value.serialNumber === SERIAL).flatMap(meter => meter.publicKeys);
            const key   = keys.find(candidate => request.keyId === undefined || candidate['@id'] === request.keyId) ?? fail(`${file}: no key of the meter`);
            anchor(`the identification of the meter key of ${file}`, sha256(Buffer.from(key.key, 'base64')), key['@id']);
            accept({ id, kind: 'meterKey', basis: basis('Meter-key association', 'VerifiedMeterKeyBinding.cs'), description,
                     trust: bootstrapOf(file, session.generatedAt), proof: ref(file, '/poiEvidence/chargingStationProof'),
                     request: { evseId: EVSE, meterSerialNumber: SERIAL, keyFormat: 'spki-der', ...request },
                     result: { evseId: EVSE, chargingStationId: 'DE*POI*S1', meterId: 'DE*POI*M1', meterSerialNumber: SERIAL, keyId: key['@id'], keyIdScheme: 'sha256-spki',
                               canonicalKeyId: coseThumbprintOfSPKI(key.key), association: 'current-snapshot' } });
        };
        anchor('the meter key of POISession', at('POISession/completed-session-with-evse-proof.chargy', '/publicKey') && sha256(Buffer.from(at('POISession/completed-session-with-evse-proof.chargy', '/publicKey'), 'base64')), session.meterKeyId);
        meterKey('meterKey-session', 'POISession/completed-session-with-evse-proof.chargy', 'The key of the meter of DE*POI*E1*1 its station proof gives, at the time the session was generated.');
        meterKey('meterKey-container-key-conflict', 'POISession/container-key-conflict.chargy', `${said('POISession', 'container-key-conflict.chargy')}: the proof gives the same key; the key of the container is no input of the binding.`);
        meterKey('meterKey-foreign-key', 'POISession/foreign-meter-key-proof.chargy', `${said('POISession', 'foreign-meter-key-proof.chargy')}: the binding is of the key the proof gives; that the readings do not verify with it is the app's check.`);
        meterKey('meterKey-tampered-end-reading', 'POISession/tampered-end-reading.chargy', `${said('POISession', 'tampered-end-reading.chargy')}: the binding is of the proof alone.`);
        meterKey('meterKey-ambiguous-by-id', 'POISession/ambiguous-meter-keys.chargy', `${said('POISession', 'ambiguous-meter-keys.chargy')}: asked for one by its identification, that one is bound.`,
                 { keyId: session.meterKeyId });
    }

    // ---- Historical meter evidence (HistoricalMeterEvidence): the keys of the meter at the signed times of the readings,
    //      with the operator of that time; its publication in a checkpoint of the operator, witnessed where the verifier
    //      trusts a witness, missing where the evidence gives none. Neither independent time is proven.
    {
        const history = provenance('POIHistory');
        const times   = [ history.begin, history.end ];
        const keyIdOf = (file, index) => at(file, '/poiEvidence/historicalEvidence/versions/' + index + '/chargingStationProof') &&
                                         all(at(file, `/poiEvidence/historicalEvidence/versions/${index}/chargingStationProof`), value => value.serialNumber === SERIAL)[0].publicKeys[0]['@id'];
        const historical = (id, file, description, publications, keyIds, { trust = bootstrapOf(file, history.evaluatedAt), policy } = {}) =>
            accept({ id, kind: 'historicalMeterEvidence', basis: basis('Historical meter evidence', 'HistoricalMeterEvidence.cs'), description, trust,
                     evidence: ref(file, '/poiEvidence/historicalEvidence'), request: { evseId: EVSE, meterSerialNumber: SERIAL, measurementTimes: times, keyFormat: 'spki-der' },
                     ...(policy === undefined ? {} : { policy }),
                     result: { bindings: keyIds.map(keyId => ({ meterId: 'DE*POI*M1', keyId, association: 'historical-attestation' })), publications, independentTime: 'not-proven' } });
        const ARCHIVED = 'POIHistory/archived-session.chargy';
        const archived = keyIdOf(ARCHIVED, 0);
        historical('historical-archived', ARCHIVED, `${said('POIHistory', 'archived-session.chargy')}.`, [ 'rno-checkpoint' ], [ archived, archived ]);
        historical('historical-archived-witnessed', ARCHIVED, 'The same, with the witness of trusted-witnesses.json trusted and one witness required: the checkpoint is witnessed.', [ 'witnessed-checkpoint' ], [ archived, archived ],
                   { policy: { witnesses: ref('POIHistory/trusted-witnesses.json'), requiredWitnesses: 1 } });
        historical('historical-archived-saved-statement', ARCHIVED, 'The same, from a historical trust context of the key statement the proof of that time gives, expired today.', [ 'rno-checkpoint' ], [ archived, archived ],
                   { trust: bootstrapOf(ARCHIVED, history.evaluatedAt, 'historical', '/poiEvidence/historicalEvidence/versions/0/chargingStationProof/roamingNetwork/operator/keyStatement') });
        historical('historical-expired-bootstrap', 'POIHistory/expired-bootstrap-session.chargy', `${said('POIHistory', 'expired-bootstrap-session.chargy')}: a historical trust context of it.`, [ 'rno-checkpoint' ], [ archived, archived ],
                   { trust: bootstrapOf('POIHistory/expired-bootstrap-session.chargy', history.evaluatedAt, 'historical') });
        historical('historical-missing-checkpoint', 'POIHistory/missing-checkpoint.chargy', `${said('POIHistory', 'missing-checkpoint.chargy')}.`, [ 'missing' ], [ archived, archived ]);
        historical('historical-key-rotation', 'POIHistory/key-rotation.chargy', `${said('POIHistory', 'key-rotation.chargy')}.`, [ 'missing', 'missing' ],
                   [ keyIdOf('POIHistory/key-rotation.chargy', 0), keyIdOf('POIHistory/key-rotation.chargy', 1) ]);
    }

    // ---- Prices bound to a session (SessionPriceEvidence): the verdicts both give, each apart - the signatures of the
    //      price statements, the agreement of the CPO, the price it binds, its publication in a checkpoint, and, with a
    //      policy of witnesses the verifier accepted, whether it was public before the signed start. The digest of the
    //      selected statement is one of the evidence; the start document is the SHA-256 of the signed start reading.
    // Where a price is selected, the organizations that witnessed its publication before the start: none without a
    // policy of witnesses; where none is, nothing was looked at (null).
    // Of the documents made here (chargy/POIPrices) where one is made, else of the run; `frozen`, of the run in any case.
    const priceCase = (set, file, request = {}, frozen = false) =>
        ({ trust: bootstrapOf(`${set}/${file}`, provenance(set).evaluatedAt ?? provenance(set).now, 'historical', undefined, frozen ? frozenRef : ref),
           evidence: (frozen ? frozenRef : ref)(`${set}/${file}`, '/poiEvidence/priceEvidence'),
           request: { evseId: EVSE, meterSerialNumber: SERIAL, chargingStarted: provenance(set).chargingStarted, startDocumentSHA256: sha256(utf8((frozen ? frozenAt : at)(`${set}/${file}`, '/ocmfBegin'))), ...request } });
    const priceVector = (id, set, file, description, verdicts, selected, { policy, organizations = selected === null ? null : [], request, specified, deviates, frozen = false } = {}) => {
        const [ signatures, agreement, applicability, publication, publicationBeforeStart ] = verdicts.split(' ');
        const evidence  = (frozen ? frozenAt : at)(`${set}/${file}`, '/poiEvidence/priceEvidence');
        if (selected !== null && !(evidence.priceStatements ?? []).some(statement => sha256(utf8(canonical({ '@context': CONTEXTS.priceStatement, ...without(statement, 'value') }))) === selected.digest))
            fail(`${set}/${file}: the selected digest ${selected.digest} is of no statement of the evidence`);
        accept({ id, kind: 'sessionPrice', basis: specified ?? basis(policy === undefined ? 'Session-bound prices' : 'Independent price publication receipts', policy === undefined ? 'SessionPriceEvidence.cs' : 'PricePublication.cs'),
                 description, ...priceCase(set, file, request, frozen),
                 ...(policy === undefined ? {} : { policy }),
                 result: { signatures, agreement, applicability, publication, publicationBeforeStart, customerConsent: 'not-proven', witnessedBy: [], selected, organizations },
                 ...(deviates === undefined ? {} : deviation(deviates)) });
    };
    const ED      = (energyPerKWh = '0.35') => ({ digest: 'e3581482ba56a562f612a0f70fa08be468e32d74bed90072d6f4e55a746259ac', algorithm: 'Ed25519', energyPerKWh });
    const prices  = (name, verdicts, selected) => priceVector(`sessionPrice-${name}`, 'POIPrices', `${name}.chargy`, `${said('POIPrices', `${name}.chargy`)}.`, verdicts, selected);

    prices('session-with-price',    'valid valid bound valid not-proven',              ED());
    prices('pqc-price',             'valid valid bound valid not-proven',              { digest: 'b64d5e0eacd749ecfcaa1c787a2768537d6e8b1ee65e41fc916bff54807fee57', algorithm: 'ML-DSA-65', energyPerKWh: '0.35' });
    prices('decimal-price',         'valid valid bound valid not-proven',              { digest: 'd4c9c5396af7c78dd5ef5c69ddf8eebf5742c2347345bc4c037289861dfccdd3', algorithm: 'Ed25519', energyPerKWh: '0.3500' });
    prices('empty-prices',          'missing missing missing missing not-proven',      null);
    prices('missing-agreement',     'valid missing unbound valid not-proven',          ED(null));
    prices('missing-publication',   'valid valid bound missing not-proven',            ED());
    prices('invalid-signature',     'invalid missing invalid missing not-proven',      null);
    prices('wrong-evse',            'valid missing invalid missing not-proven',        null);
    prices('expired-price',         'valid invalid missing missing not-proven',        null);
    prices('unauthorized-key',      'invalid missing invalid missing not-proven',      null);
    prices('wrong-session',         'valid invalid invalid missing not-proven',        null);
    prices('contract-mode',         'valid valid unsupported valid not-proven',        ED());
    prices('variable-binding',      'valid valid unsupported valid not-proven',        ED());
    prices('signed-rate-conflict',  'valid valid bound valid not-proven',              ED());
    prices('tampered-publication',  'valid valid bound invalid not-proven',            ED());
    prices('checkpoint-fork',       'valid valid bound valid not-proven',              ED());
    prices('split-price-chain',     'valid missing invalid missing not-proven',        null);
    prices('broken-price-chain',    'valid missing invalid missing not-proven',        null);
    prices('ambiguous-offers',      'valid missing ambiguous missing not-proven',      null);

    // ---- A price restricted by a restriction POI does not define (SPECIFICATION.md 2, 12.1): its elements are not written
    //      as a charging tariff holds them, so no price statement, refused as read, before its signature is looked at, as
    //      of an invalid signature. ChargyWebApp restricts it by max_kwh, the name of OCPI; what it meant, a conditional
    //      element, a restriction of POI would show, e.g. maxEnergy.
    {
        const CONDITIONAL  = 'POIPrices/conditional-price.chargy';
        const RESTRICTIONS = 'libs/WWCP_POI/WWCP_POI3/RoamingNetwork/ChargingTariff/ChargingTariffRestrictions.cs';
        const defined      = [ ...source(RESTRICTIONS).matchAll(/public const String\s+\w+\s*=\s*"([A-Za-z@]+)";/gu) ].map(match => match[1]);
        const statement    = frozenAt(CONDITIONAL, '/poiEvidence/priceEvidence/priceStatements/0');
        const restrictions = statement.priceStatus.prices.flatMap(price => price.elements).flatMap(element => element.restrictions === undefined ? [] : [ element.restrictions ]);
        const undefinedOf  = restrictions.flatMap(restriction => Object.keys(restriction)).filter(name => !defined.includes(name));
        if (!defined.includes('maxEnergy') || restrictions.length !== 1 || undefinedOf.join() !== 'max_kwh')
            fail(`${CONDITIONAL}: no price statement of one element restricted by max_kwh alone, which ${RESTRICTIONS} does not define`);
        quoted(SPEC, 'the `elements` are written as a charging tariff holds them (section 2, "Written forms"), as a version holds the', 'that the elements of a price status are written as a charging tariff holds them');
        priceVector('sessionPrice-conditional-price', 'POIPrices', 'conditional-price.chargy',
                    `${said('POIPrices', 'conditional-price.chargy')}: its element is restricted by max_kwh, which POI does not define (OCPI's name of its maxEnergy), so that its elements are not written as a charging tariff holds them. It is no price statement, refused as read, before its signature is looked at: no statement of the evidence holds, as of an invalid signature.`,
                    'invalid missing invalid missing not-proven', null, { specified: `${SPEC}, 2, 12.1`, frozen: true });
    }

    // ---- A price naming no identification of a charging tariff (SPECIFICATION.md 2, 12.1): no price statement, refused
    //      as read, before its signature is looked at, so that none of the evidence holds, as of an invalid signature.
    //      What ChargyWebApp meant, a tariff outside the references of the EVSE, a tariff of the operator's pattern would
    //      show. Both refuse it so since WWCP_POI.TS `80afec7` (D16, fixed).
    {
        const FOREIGN   = 'POIPrices/foreign-tariff.chargy';
        const statement = frozenAt(FOREIGN, '/poiEvidence/priceEvidence/priceStatements/0');
        const operator  = frozenAt(FOREIGN, '/poiEvidence/priceEvidence/chargingStationProof/roamingNetwork/chargingStationOperators/0');
        const tariffIds = (operator.chargingTariffs ?? []).map(tariff => tariff['@id']);
        const named     = statement.priceStatus.prices.map(price => price.chargingTariffId);
        // As ChargingTariff_Id reads it: {operatorId}*T{suffix}.
        const TARIFF_ID = /^[A-Za-z]{2}\*?[A-Za-z0-9]{3}\*?T[A-Za-z0-9_][A-Za-z0-9_*.$€-]{0,49}$/u;
        if (statement.signer !== operator['@id'] || tariffIds.length === 0 || !tariffIds.every(id => TARIFF_ID.test(id)) || named.length !== 1 || TARIFF_ID.test(named[0]))
            fail(`${FOREIGN}: no statement of ${operator['@id']}, whose tariffs ${tariffIds.join(', ')} are of the pattern, naming one price of a tariff that is not`);
        quoted(SPEC, 'identified as `ChargingTariff_Id`, `{operatorId}*T{suffix}` (`DE*GEF*T_AC`)', 'how a charging tariff is identified');
        quoted(SPEC, 'A statement naming another text is no price statement and is',                'that a price statement naming another text is refused');
        priceVector('sessionPrice-foreign-tariff', 'POIPrices', 'foreign-tariff.chargy',
                    `${said('POIPrices', 'foreign-tariff.chargy')}: its price names the charging tariff '${named[0]}', which is no identification of a charging tariff, {operatorId}*T{suffix}, as those of ${operator['@id']} are (${tariffIds.join(', ')}). It is no price statement, refused as read, before its signature is looked at: no statement of the evidence holds, as of an invalid signature.`,
                    'invalid missing invalid missing not-proven', null, { specified: `${SPEC}, 2, 12.1`, frozen: true });
    }

    // ---- What the two counterexamples meant, made here (chargy/POIPrices): a price of a tariff of the operator's pattern
    //      none of the references of the EVSE names, and an element restricted by a restriction POI defines.
    {
        const digestOf = (file) => sha256(utf8(canonical({ '@context': CONTEXTS.priceStatement, ...without(at(`POIPrices/${file}`, '/poiEvidence/priceEvidence/priceStatements/0'), 'value') })));
        const evseOf   = at('POIPrices/foreign-tariff.chargy', '/poiEvidence/priceEvidence/chargingStationProof');
        const named    = at('POIPrices/foreign-tariff.chargy', '/poiEvidence/priceEvidence/priceStatements/0').priceStatus.prices.map(price => price.chargingTariffId);
        const ofEVSE   = all(evseOf, value => value['@id'] === EVSE).flatMap(evse => evse.chargingTariffIds ?? []);
        if (named.join() !== 'DE*POI*T2' || ofEVSE.length === 0 || ofEVSE.includes('DE*POI*T2'))
            fail(`chargy/POIPrices/foreign-tariff.chargy: no price of DE*POI*T2 alone, a tariff none of the references of ${EVSE} names (${ofEVSE.join(', ')})`);
        priceVector('sessionPrice-tariff-of-another-evse', 'POIPrices', 'foreign-tariff.chargy',
                    `${OWN_SAYS['foreign-tariff.chargy']}: the references of ${EVSE} name ${ofEVSE.join(', ')}. Its signature holds, but no price of it applies to the EVSE: none is selected, nor its agreement and publication looked at, as of a price of another EVSE.`,
                    'valid missing invalid missing not-proven', null);
        const restricted = at('POIPrices/conditional-price.chargy', '/poiEvidence/priceEvidence/priceStatements/0').priceStatus.prices[0].elements[0].restrictions;
        if (canonical(restricted) !== '{"maxEnergy":5}')
            fail('chargy/POIPrices/conditional-price.chargy: no element restricted by maxEnergy alone');
        priceVector('sessionPrice-conditional-element', 'POIPrices', 'conditional-price.chargy',
                    `${OWN_SAYS['conditional-price.chargy']}, a restriction POI defines. Signed, agreed and published, its price is selected, but its rate is not given: an element under a restriction is no rate a verifier applies to the session.`,
                    'valid valid unsupported valid not-proven', { digest: digestOf('conditional-price.chargy'), algorithm: 'Ed25519', energyPerKWh: null });
    }

    // ---- Receipts of witnesses (PricePublicationVerification): without a policy of witnesses, no receipt counts; with
    //      witness-policy.json accepted, two organizations, receipts of organization A (two Ed25519 keys, counting once)
    //      and B (ML-DSA-65) before the signed start.
    {
        const POLICY = { publicationPolicy: ref('POIPublication/witness-policy.json') };
        const A = 'Demo independent organization A', B = 'Demo independent organization B';
        const publication = (name, description, withoutPolicy, withPolicy, organizations) => {
            priceVector(`publication-${name}`, 'POIPublication', `${name}.chargy`, `${description}; no policy of witnesses accepted.`, `valid valid bound valid ${withoutPolicy}`, ED());
            priceVector(`publication-${name}-accepted`, 'POIPublication', `${name}.chargy`, `${description}; witness-policy.json accepted.`, `valid valid bound valid ${withPolicy}`, ED(), { policy: POLICY, organizations });
        };
        publication('session-before-start', 'Receipts of organizations A and B, both before the signed start',                       'not-proven', 'witnessed-before-signed-start', [ A, B ]);
        publication('no-receipts',          'No receipts',                                                                          'not-proven', 'not-proven', []);
        publication('late-receipt',         'The receipt of organization B after the signed start',                                  'not-proven', 'not-proven', [ A ]);
        publication('clock-overlap',        'The receipt of organization B within its clock error of the signed start',              'not-proven', 'not-proven', [ A ]);
        publication('same-organization',    'Both receipts of organization A, of its two keys: one organization',                    'not-proven', 'not-proven', [ A ]);
        publication('unknown-witness',      'A receipt of a witness the policy does not name',                                       'not-proven', 'not-proven', [ A ]);
        publication('wrong-price',          'A receipt of another price statement',                                                  'not-proven', 'invalid', [ A ]);
        publication('wrong-signed-price',   'A receipt binding another signed price statement',                                      'not-proven', 'invalid', [ A ]);
        publication('wrong-tariff',         'A receipt binding another tariff',                                                      'not-proven', 'invalid', [ A ]);
        publication('wrong-checkpoint',     'A receipt naming another checkpoint',                                                   'not-proven', 'invalid', [ A ]);
        publication('tampered-receipt',     'A receipt whose source URL was changed after it was signed',                            'not-proven', 'invalid', [ A ]);
        publication('future-receipt',       'A receipt signed after the time of the verification',                                   'not-proven', 'invalid', [ A ]);
        publication('private-source',       'A receipt of a private source URL, changed after it was signed',                         'invalid',    'invalid', [ A ]);
    }

    // ---- Trust transitions (VerifiedTrustTransition), of the trust anchor and operator of POITrustTransitions/vectors.json
    //      at its time: both quorums signed; the policy of the next anchor, calculated here; a transition opening epoch 2.
    const TT        = 'POITrustTransitions/vectors.json';
    const NOW       = at(TT, '/now');
    const ttTrust   = { anchor: ref(TT, '/anchor'), keyStatement: ref(TT, '/operator/keyStatement'), at: NOW, context: 'current' };
    const transition = (id, file, pointer, description, epoch) =>
        accept({ id, kind: 'trustTransition', basis: basis('CPO envelope authority and compact trust succession', 'TrustTransition.cs'), description, trust: ttTrust,
                 operator: ref(TT, '/operator'), transition: ref(file, pointer), acceptedAt: NOW, sequence: 0,
                 result: { requiredConsensus: 2, signedByOld: 2, signedByNext: 2, policyId: policyIdOf(at(file, pointer + '/toAnchor')), epoch } });
    transition('trustTransition-policy', 'POITrustTransitions/policy-transition.json', '', 'Old and new two-holder quorums sign a new anchor URL, identity keys, statement and certificates.', 1);
    transition('trustTransition-epoch', 'POITrustTransitions/epoch-transition.json', '', 'A transition opening epoch 2: the final checkpoint of epoch 1, the deterministic genesis of epoch 2 and its first checkpoint.', 2);
    transition('trustTransition-policy-of-vectors', TT, '/policy', 'The policy transition of vectors.json, which WWCP_POI.TS and WWCP_POI3 share.', 1);
    transition('trustTransition-epoch-of-vectors', TT, '/epoch', 'The epoch transition of vectors.json, which WWCP_POI.TS and WWCP_POI3 share.', 2);

    // ---- The keys a CPO signs its documents with (AuthorizedChargingDocumentKeys): of the proof of its station.
    accept({ id: 'chargingDocumentKeys-base', kind: 'chargingDocumentKeys', basis: basis('CPO envelope authority and compact trust succession', 'AuthorizedChargingDocumentKeys.cs'),
             description: 'The keys DE*POI may sign its charging documents with, of the proof of DE*POI*E1*1: its one Ed25519 key, as COSE names its algorithm.',
             trust: ttTrust, proof: ref(TT, '/baseProof'), request: { evseId: EVSE, operatorId: 'DE*POI', at: '2026-11-01T00:05:01.000Z' },
             result: { chargingStationId: 'DE*POI*S1', keys: all(at(TT, '/baseProof'), value => Array.isArray(value.signingKeys) && value['@id'] === 'DE*POI')[0].signingKeys.map(key => ({ id: key['@id'], algorithm: 'EdDSA-Ed25519' })) } });

    // ---- What is calculated alone, here as well: policy identities, the digest of a key statement, what a receipt binds.
    for (const [ id, pointer, description ] of [ [ 'trustPolicyId-anchor', '/anchor', 'The trust anchor of vectors.json.' ],
                                               [ 'trustPolicyId-target', '/targetAnchor', 'The trust anchor a transition of vectors.json delegates to.' ] ])
        accept({ id, kind: 'trustPolicyId', basis: basis('CPO envelope authority and compact trust succession', 'TrustTransition.cs'), description: `${description} Its policy identity: the SHA-256 of the canonical JSON of {network, holders, minConsensus, urls}.`,
                 trustAnchor: ref(TT, pointer), result: { policyId: policyIdOf(at(TT, pointer)) } });
    for (const [ id, pointer, description ] of [ [ 'keyStatementDigest-operator', '/operator/keyStatement', 'The key statement of the operator of vectors.json.' ],
                                               [ 'keyStatementDigest-target', '/targetOperator/keyStatement', 'The key statement of the operator a transition of vectors.json delegates to.' ] ])
        accept({ id, kind: 'keyStatementDigest', basis: basis('CPO envelope authority and compact trust succession', 'TrustTransition.cs'), description: `${description} Its digest: the SHA-256 of its content, with its @context, without its signatures.`,
                 keyStatement: ref(TT, pointer), result: { digest: keyStatementDigestOf(at(TT, pointer)) } });
    {
        const SESSION   = 'POIPublication/session-before-start.chargy';
        const statement = '/poiEvidence/priceEvidence/priceStatements/0';
        const tariff    = '/poiEvidence/priceEvidence/chargingStationProof/roamingNetwork/chargingStationOperators/0/chargingTariffs/0';
        accept({ id: 'offerHashes-session-before-start', kind: 'offerHashes', basis: basis('Independent price publication receipts', 'PricePublication.cs'),
                 description: 'What a receipt binds of an offer: the SHA-256 of the canonical JSON of the price statement as signed, its value included, and of the tariff selected.',
                 priceStatement: ref(SESSION, statement), tariff: ref(SESSION, tariff),
                 result: { priceStatementSHA256: sha256(utf8(canonical(at(SESSION, statement)))), tariffSHA256: sha256(utf8(canonical(at(SESSION, tariff)))) } });
    }

    // ---- Refusals: what both refuse, each with its control - the same check, of what the refusal is about given
    //      otherwise, which both take - and what changes from the control to the refusal, checked here: in the case
    //      ("changes", all of it), and where a document of the run is another one, in that document ("documentChanges",
    //      prefixes covering every difference, each one at least). Where both word the refusal alike, "reason" names it.
    const REFUSAL_FIELDS = [ 'id', 'kind', 'basis', 'description', 'expected', 'control', 'reason', 'changes', 'documentChanges' ];
    const refuse = ({ control, changes, documentChanges, reason, ...vector }) => {
        const refused   = Object.fromEntries(Object.entries(vector).filter(([ key ]) => !REFUSAL_FIELDS.includes(key)));
        anchor(`what ${vector.id} changes`, JSON.stringify(differences(refused, control).sort()), JSON.stringify([ ...changes ].sort()));
        const documents = [ ...new Set(changes.filter(path => /\/(file|pointer)$/.test(path)).map(path => path.replace(/\/(file|pointer)$/, ''))) ];
        if (documents.length !== (documentChanges === undefined ? 0 : 1))
            fail(`${vector.id}: ${documents.length} documents change, ${documentChanges === undefined ? 'none' : 'one'} named`);
        for (const path of documents) {
            const named  = (object) => path.split('/').slice(1).reduce((item, key) => item[key], object);
            const found  = differences(chargyAt(named(refused).file, named(refused).pointer), chargyAt(named(control).file, named(control).pointer));
            const covers = (prefix, difference) => difference === prefix || difference.startsWith(prefix + '/');
            const loose  = found.filter(difference => !documentChanges.some(prefix => covers(prefix, difference)));
            const unused = documentChanges.filter(prefix => !found.some(difference => covers(prefix, difference)));
            if (loose.length > 0 || unused.length > 0)
                fail(`${vector.id}: the document of ${path} differs${loose.length > 0 ? ` in ${loose.join(', ')} as well` : ''}${unused.length > 0 ? ` not in ${unused.join(', ')}` : ''}`);
        }
        vectors.push({ expected: 'refused', ...vector, control, ...(reason === undefined ? {} : { reason }), changes, ...(documentChanges === undefined ? {} : { documentChanges }) });
    };

    // Both word these alike, WWCP_POI3 with a "!" at the end.
    const NO_TRIAL  = 'Select exactly one explicitly identified meter key; no trial verification across keys';
    const NO_MATCH  = 'The signed meter identity does not match the selected EVSE meter';
    const OTHER_EVSE = 'DE*POI*E9*9';
    const statementNotValid = (time, statement) => `The key statement is not valid at ${time}: it was signed at ${statement.signedAt} and is valid until ${statement.validUntil}!`;

    // ---- The key of a meter: a proof of another meter, a key or meter or EVSE the proof does not give, two keys and none
    //      asked for, a key of a SubjectPublicKeyInfo read as a COSE key. The trust is the bootstrap of the session.
    {
        const SESSION   = 'POISession/completed-session-with-evse-proof.chargy';
        const session   = provenance('POISession');
        const B         = basis('Meter-key association', 'VerifiedMeterKeyBinding.cs');
        const meterCase = (file, request = {}) => ({ trust: bootstrapOf(SESSION, session.generatedAt), proof: ref(file, '/poiEvidence/chargingStationProof'),
                                                     request: { evseId: EVSE, meterSerialNumber: SERIAL, keyFormat: 'spki-der', ...request } });
        const refuseKey = (id, description, refused, control, reason, changes, documentChanges) =>
            refuse({ id, kind: 'meterKey', basis: B, description, ...refused, control, reason, changes, documentChanges });
        const AMBIGUOUS = 'POISession/ambiguous-meter-keys.chargy', WRONG_METER = 'POISession/wrong-meter-proof.chargy';
        const SERIAL_OF_THE_EVSE = '/roamingNetwork/chargingStationOperators/0/chargingPools/0/chargingStations/@leaves/0/@entity/EVSEs/0/energyMeter/serialNumber';
        anchor('the serial number of the meter of DE*POI*E1*1 in its proof', chargyAt(SESSION, '/poiEvidence/chargingStationProof' + SERIAL_OF_THE_EVSE), SERIAL);

        refuseKey('meterKey-ambiguous', `${said('POISession', 'ambiguous-meter-keys.chargy')}: no key asked for by its identification.`,
                  meterCase(AMBIGUOUS), meterCase(AMBIGUOUS, { keyId: session.meterKeyId }), NO_TRIAL, [ '/request/keyId' ]);
        refuseKey('meterKey-unknown-key', 'A key of the meter asked for by an identification the proof does not give.',
                  meterCase(SESSION, { keyId: '00'.repeat(32) }), meterCase(SESSION, { keyId: session.meterKeyId }), NO_TRIAL, [ '/request/keyId' ]);
        refuseKey('meterKey-wrong-meter-proof', `${said('POISession', 'wrong-meter-proof.chargy')}: the proof, attested again, names another serial number for the meter of the EVSE.`,
                  meterCase(WRONG_METER), meterCase(SESSION), NO_MATCH, [ '/proof/file' ], [ SERIAL_OF_THE_EVSE, '/commitId', '/revision', '/attestations' ]);
        refuseKey('meterKey-other-serial', 'The key of a meter of another serial number than the proof gives the EVSE.',
                  meterCase(SESSION, { meterSerialNumber: 'CHARGY-POI-METER-002' }), meterCase(SESSION), NO_MATCH, [ '/request/meterSerialNumber' ]);
        refuseKey('meterKey-other-meter', 'The key of the meter of the EVSE asked for with the identification of another meter.',
                  meterCase(SESSION, { meterId: 'DE*POI*M2' }), meterCase(SESSION, { meterId: 'DE*POI*M1' }), NO_MATCH, [ '/request/meterId' ]);
        refuseKey('meterKey-other-evse', 'The key of the meter of an EVSE the proof does not give.',
                  meterCase(SESSION, { evseId: OTHER_EVSE }), meterCase(SESSION), `The proof gives no charging station of the EVSE '${OTHER_EVSE}' completely!`, [ '/request/evseId' ]);
        refuseKey('meterKey-cose-key', 'The key of the meter, a SubjectPublicKeyInfo, read as a COSE key. Both refuse it as no COSE key, worded otherwise: WWCP_POI3 names the COSE key, WWCP_POI.TS its CBOR decoder.',
                  meterCase(SESSION, { keyFormat: 'cose-key' }), meterCase(SESSION), undefined, [ '/request/keyFormat' ]);
    }

    // ---- Historical meter evidence: the counterexamples of POIHistory against archived-session.chargy, a publication or
    //      more witnesses required than the evidence gives, the bootstrap expired today, another EVSE or meter, a time
    //      before the key statement of the evidence.
    {
        const history   = provenance('POIHistory');
        const ARCHIVED  = 'POIHistory/archived-session.chargy', EXPIRED = 'POIHistory/expired-bootstrap-session.chargy';
        const B         = basis('Historical meter evidence', 'HistoricalMeterEvidence.cs');
        const histCase  = (file, { request = {}, trust = bootstrapOf(ARCHIVED, history.evaluatedAt), policy } = {}) =>
            ({ trust, evidence: ref(file, '/poiEvidence/historicalEvidence'),
               request: { evseId: EVSE, meterSerialNumber: SERIAL, measurementTimes: [ history.begin, history.end ], keyFormat: 'spki-der', ...request },
               ...(policy === undefined ? {} : { policy }) });
        const refuseHistory = (id, description, refused, control, reason, changes, documentChanges) =>
            refuse({ id, kind: 'historicalMeterEvidence', basis: B, description, ...refused, control, reason, changes, documentChanges });
        const coverage  = (time, why) => `No historical EVSE/meter/key coverage at ${time}: ${why}`;
        const WITNESSED = (requiredWitnesses) => ({ witnesses: ref('POIHistory/trusted-witnesses.json'), requiredWitnesses });
        const MISSING   = 'Required historical commit inclusion evidence is missing';
        const swapped   = (name, why, reason, documentChanges) =>
            refuseHistory(`historical-${name}`, `${said('POIHistory', `${name}.chargy`)}: ${why}`, histCase(`POIHistory/${name}.chargy`), histCase(ARCHIVED), reason, [ '/evidence/file' ], documentChanges);

        swapped('conflicting-assignments', 'its second version gives another key at the same times.', 'Conflicting historical key assignments cover the same measurement time', [ '/versions/1' ]);
        swapped('wrong-period', 'the attestations of the proof of its first version, signed again at another time.',
                coverage(history.begin, `Valid attestations of trusted keys of 0 holders attest the root effectiveTree:sha256:hex:${rootOfProof(at('POIHistory/wrong-period.chargy', '/poiEvidence/historicalEvidence/versions/0/chargingStationProof').roamingNetwork)} of the proof, not of 2!`),
                [ '/versions/0/chargingStationProof/attestations' ]);
        swapped('tampered-checkpoint', 'the commit its inclusion proof names is another.', 'The proof does not lead to the commits of the checkpoint!', [ '/versions/0/commitProof/leaf/commitId' ]);

        refuseHistory('historical-missing-checkpoint-witness-required', `${said('POIHistory', 'missing-checkpoint.chargy')}; one witness of trusted-witnesses.json required.`,
                      histCase('POIHistory/missing-checkpoint.chargy', { policy: WITNESSED(1) }), histCase('POIHistory/missing-checkpoint.chargy'), MISSING, [ '/policy' ]);
        refuseHistory('historical-key-rotation-publication-required', `${said('POIHistory', 'key-rotation.chargy')}; a publication required.`,
                      histCase('POIHistory/key-rotation.chargy', { policy: { requirePublication: true } }), histCase('POIHistory/key-rotation.chargy'), MISSING, [ '/policy' ]);
        refuseHistory('historical-archived-two-witnesses', 'archived-session.chargy, two witnesses required: the checkpoint is witnessed by one.',
                      histCase(ARCHIVED, { policy: WITNESSED(2) }), histCase(ARCHIVED, { policy: WITNESSED(1) }), 'Historical checkpoint lacks the locally required RNO/witness quorum', [ '/policy/requiredWitnesses' ]);
        refuseHistory('historical-expired-bootstrap-current', `${said('POIHistory', 'expired-bootstrap-session.chargy')}: a current trust context of it.`,
                      histCase(EXPIRED, { trust: bootstrapOf(EXPIRED, history.evaluatedAt) }), histCase(EXPIRED, { trust: bootstrapOf(EXPIRED, history.evaluatedAt, 'historical') }),
                      statementNotValid(history.evaluatedAt, at(EXPIRED, '/poiEvidence/bootstrap/keyStatement/keyStatement')), [ '/trust/context' ]);
        refuseHistory('historical-other-evse', 'archived-session.chargy, asked for another EVSE.',
                      histCase(ARCHIVED, { request: { evseId: OTHER_EVSE } }), histCase(ARCHIVED), 'Historical evidence belongs to another EVSE', [ '/request/evseId' ]);
        refuseHistory('historical-other-serial', 'archived-session.chargy, asked for a meter of another serial number.',
                      histCase(ARCHIVED, { request: { meterSerialNumber: 'CHARGY-POI-METER-002' } }), histCase(ARCHIVED), coverage(history.begin, NO_MATCH), [ '/request/meterSerialNumber' ]);
        const BEFORE = '2026-05-01T10:00:00.000Z';
        refuseHistory('historical-before-statement', 'archived-session.chargy, its first reading at a time before the key statement its first version gives was signed.',
                      histCase(ARCHIVED, { request: { measurementTimes: [ BEFORE, history.end ] } }), histCase(ARCHIVED),
                      coverage(BEFORE, statementNotValid(BEFORE, at(ARCHIVED, '/poiEvidence/historicalEvidence/versions/0/chargingStationProof/roamingNetwork/operator/keyStatement'))), [ '/request/measurementTimes/0' ]);
    }

    // ---- Prices bound to a session: another EVSE, a start after the verification or before the key statement; and, taken,
    //      another meter or start document than the agreement binds.
    {
        const B       = basis('Session-bound prices', 'SessionPriceEvidence.cs');
        const PRICE   = 'session-with-price.chargy';
        const control = priceCase('POIPrices', PRICE);
        const refusePrice = (id, description, request, reason) =>
            refuse({ id, kind: 'sessionPrice', basis: B, description, ...priceCase('POIPrices', PRICE, request), control, reason, changes: Object.keys(request).map(key => `/request/${key}`) });
        refusePrice('sessionPrice-other-evse', 'The price of session-with-price.chargy, asked for another EVSE.', { evseId: OTHER_EVSE }, 'Price evidence belongs to another EVSE');
        refusePrice('sessionPrice-started-after-verification', 'The price of session-with-price.chargy, of a session started after the time of the verification.',
                    { chargingStarted: new Date(Date.parse(provenance('POIPrices').evaluatedAt) + 1000).toISOString() }, 'Invalid original price context');
        refusePrice('sessionPrice-started-before-statement', 'The price of session-with-price.chargy, of a session started before the key statement its station proof gives was signed.',
                    { chargingStarted: '2026-05-01T10:00:00.000Z' }, statementNotValid('2026-05-01T10:00:00.000Z', at(`POIPrices/${PRICE}`, '/poiEvidence/priceEvidence/chargingStationProof/roamingNetwork/operator/keyStatement')));
        priceVector('sessionPrice-other-meter', 'POIPrices', PRICE, 'The price of session-with-price.chargy, asked for a meter of another serial number: the agreement binds the meter, so neither it nor the price holds.',
                    'valid invalid invalid missing not-proven', null, { request: { meterSerialNumber: 'CHARGY-POI-METER-002' } });
        priceVector('sessionPrice-other-start-document', 'POIPrices', PRICE, 'The price of session-with-price.chargy, with the SHA-256 of its end reading as the start document: the agreement binds the start, so neither it nor the price holds.',
                    'valid invalid invalid missing not-proven', null, { request: { startDocumentSHA256: sha256(utf8(at(`POIPrices/${PRICE}`, '/ocmfEnd'))) } });
    }

    // ---- Trust transitions: the counterexamples of POITrustTransitions against the transitions they change, a transition
    //      out of order or accepted before it was signed.
    {
        const B        = basis('CPO envelope authority and compact trust succession', 'TrustTransition.cs');
        const POLICY   = 'POITrustTransitions/policy-transition.json', EPOCH = 'POITrustTransitions/epoch-transition.json';
        const ttCase   = (file, pointer = '', { acceptedAt = NOW, sequence = 0 } = {}) => ({ trust: ttTrust, operator: ref(TT, '/operator'), transition: ref(file, pointer), acceptedAt, sequence });
        const refuseTransition = (id, description, refused, control, reason, changes, documentChanges) =>
            refuse({ id, kind: 'trustTransition', basis: B, description, ...refused, control, reason, changes, documentChanges });
        const QUORUMS  = 'Both old and new holder quorums must sign the trust transition';
        const INTERVAL = 'Transition is expired, out of order or not accepted within its signed interval';
        const INVALID_CERTIFICATE = `The certificate of the signing key '${at('POITrustTransitions/invalid-target-certificate.json', '/toOperator/signingKeyCertificates/0/signingKey/@id')}' is invalid: The signature is invalid`;

        refuseTransition('trustTransition-missing-old-quorum', 'policy-transition.json signed by the new holders alone.',
                         ttCase('POITrustTransitions/missing-old-quorum.json'), ttCase(POLICY), QUORUMS, [ '/transition/file' ], [ '/signatures' ]);
        refuseTransition('trustTransition-missing-new-quorum', 'policy-transition.json signed by the old holders alone.',
                         ttCase('POITrustTransitions/missing-new-quorum.json'), ttCase(POLICY), QUORUMS, [ '/transition/file' ], [ '/signatures' ]);
        refuseTransition('trustTransition-tampered-target-url', 'policy-transition.json, the trust anchor it delegates to changed after both quorums signed.',
                         ttCase('POITrustTransitions/tampered-target-url.json'), ttCase(POLICY), 'The signature is invalid!', [ '/transition/file' ], [ '/toAnchor' ]);
        refuseTransition('trustTransition-invalid-target-certificate', 'policy-transition.json, both quorums signing genuinely an invalid certificate of the next operator.',
                         ttCase('POITrustTransitions/invalid-target-certificate.json'), ttCase(POLICY), INVALID_CERTIFICATE, [ '/transition/file' ], [ '/toOperator/signingKeyCertificates/0/value', '/signatures' ]);
        refuseTransition('trustTransition-invalid-target-certificate-of-vectors', 'The same of vectors.json, which WWCP_POI.TS and WWCP_POI3 share.',
                         ttCase(TT, '/invalidCertificate'), ttCase(TT, '/policy'), INVALID_CERTIFICATE, [ '/transition/pointer' ], [ '/toOperator/signingKeyCertificates/0/value', '/signatures' ]);
        refuseTransition('trustTransition-wrong-genesis', 'epoch-transition.json, signed again with another genesis of epoch 2.',
                         ttCase('POITrustTransitions/wrong-genesis.json'), ttCase(EPOCH), 'The next epoch must start from the exact deterministic genesis and final checkpoint', [ '/transition/file' ], [ '/epochChange/genesis', '/signatures' ]);
        refuseTransition('trustTransition-out-of-order', 'policy-transition.json, its sequence 0, applied as the second transition.',
                         ttCase(POLICY, '', { sequence: 1 }), ttCase(POLICY), INTERVAL, [ '/sequence' ]);
        refuseTransition('trustTransition-accepted-before-signed', 'policy-transition.json, accepted a second before it was signed.',
                         ttCase(POLICY, '', { acceptedAt: new Date(Date.parse(at(POLICY, '/signedAt')) - 1000).toISOString() }), ttCase(POLICY), INTERVAL, [ '/acceptedAt' ]);
    }

    // ---- The keys a CPO signs its documents with: of the live documents of POITrustTransitions, each of the time it was
    //      last updated - a proof giving only a key for price statements, a document of another CPO, a time after the
    //      verification; and, taken, the keys of a key transition, and of a key change the proof does not give.
    {
        const B        = basis('CPO envelope authority and compact trust succession', 'AuthorizedChargingDocumentKeys.cs');
        const live     = (name) => `POITrustTransitions/live-${name}.json`;
        const keysCase = (file, pointer, request = {}) => ({ trust: ttTrust, proof: ref(file, pointer), request: { evseId: EVSE, operatorId: 'DE*POI', ...request } });
        const liveCase = (name, request = {}) => keysCase(live(name), '/poiEvidence/chargingStationProof', { at: at(live(name), '/lastUpdated'), ...request });
        const keysOf   = (name) => all(at(live(name), '/poiEvidence/chargingStationProof'), value => Array.isArray(value.signingKeys) && value['@id'] === 'DE*POI')[0].signingKeys
                                       .filter(key => key.usages === undefined || key.usages.includes('chargeTransparencyRecords')).map(key => ({ id: key['@id'], algorithm: 'EdDSA-Ed25519' }));
        const refuseKeys = (id, description, refused, control, reason, changes, documentChanges) =>
            refuse({ id, kind: 'chargingDocumentKeys', basis: B, description, ...refused, control, reason, changes, documentChanges });

        refuseKeys('chargingDocumentKeys-price-only-key', 'live-price-only-key.json: a genuine station proof gives DE*POI one key, for price statements only. Its control is the proof of live-wrong-cpo.json, whose key is for charge transparency records as well. WWCP_POI3 words it "charge transparency records", WWCP_POI.TS "charging transparency records".',
                   liveCase('price-only-key'), liveCase('wrong-cpo'), 'The proven CPO supplies no valid keys authorized for', [ '/proof/file' ],
                   [ '/roamingNetwork/chargingStationOperators/0/signingKeys/0/usages', '/commitId', '/attestations' ]);
        refuseKeys('chargingDocumentKeys-foreign-cpo', `live-wrong-cpo.json: the document names ${at(live('wrong-cpo'), '/chargingStationOperator/@id')} as its CPO, the proof DE*POI as the operator of the EVSE.`,
                   liveCase('wrong-cpo', { operatorId: at(live('wrong-cpo'), '/chargingStationOperator/@id') }), liveCase('wrong-cpo'), 'The live document CPO is not the operator of the proven EVSE', [ '/request/operatorId' ]);
        refuseKeys('chargingDocumentKeys-after-verification', 'The keys of DE*POI of the proof of vectors.json, at a time after the verification.',
                   keysCase(TT, '/baseProof', { at: new Date(Date.parse(NOW) + 1000).toISOString() }), keysCase(TT, '/baseProof', { at: '2026-11-01T00:05:01.000Z' }), 'Invalid charging-document evaluation time', [ '/request/at' ]);
        accept({ id: 'chargingDocumentKeys-key-transition', kind: 'chargingDocumentKeys', basis: B, description: 'live-key-transition.json: the station proof gives DE*POI a second key, attested by the RNO: both keys are authorized.',
                 ...liveCase('key-transition'), result: { chargingStationId: 'DE*POI*S1', keys: keysOf('key-transition') } });
        accept({ id: 'chargingDocumentKeys-key-change-without-poi', kind: 'chargingDocumentKeys', basis: B, description: 'live-key-change-without-poi.json: the document names a second key of DE*POI the station proof does not give: only the key of the proof is authorized.',
                 ...liveCase('key-change-without-poi'), result: { chargingStationId: 'DE*POI*S1', keys: keysOf('key-change-without-poi') } });
    }

    // ---- A receipt of a witness read alone (PricePublicationReceipt): of the two organizations, and of a private source.
    {
        const B       = basis('Independent price publication receipts', 'PricePublication.cs');
        const BEFORE  = 'POIPublication/session-before-start.chargy', PRIVATE = 'POIPublication/private-source.chargy';
        const receipt = (file, index) => ({ receipt: ref(file, `/poiEvidence/priceEvidence/publicationReceipts/${index}`) });
        for (const [ index, name, description ] of [ [ 0, 'a', 'The receipt of organization A of session-before-start.chargy (Ed25519).' ], [ 1, 'b', 'The receipt of organization B of session-before-start.chargy (ML-DSA-65).' ] ])
            accept({ id: `publicationReceipt-${name}`, kind: 'publicationReceipt', basis: B, description: `${description} Its digest: the SHA-256 of its canonical JSON, its signature included.`,
                     ...receipt(BEFORE, index), result: { digest: sha256(utf8(canonical(at(BEFORE, `/poiEvidence/priceEvidence/publicationReceipts/${index}`)))) } });
        refuse({ id: 'publicationReceipt-private-source', kind: 'publicationReceipt', basis: B,
                 description: `private-source.chargy: the receipt of organization B names ${at(PRIVATE, '/poiEvidence/priceEvidence/publicationReceipts/1/publicSourceURL')} as its source, no public DNS host name - refused as read, before its signature is looked at.`,
                 ...receipt(PRIVATE, 1), control: receipt(BEFORE, 1), reason: 'Publication sources require a public DNS hostname', changes: [ '/receipt/file' ], documentChanges: [ '/publicSourceURL' ] });
    }

    return vectorFile(
        `WWCP_POI.TS 0.2.0 (README, experimental) and WWCP_POI3/Verifier of WWCP_POI; documents of test-vectors/runs/${CHARGY}`,
        'The verifier extensions of WWCP_POI.TS 0.2.0, which WWCP_POI3 has as well: no part of SPECIFICATION.md but the usages chargeTransparencyRecords and witnessPublications. Each vector names a check ("kind"), its inputs as documents of the run (a file and a JSON pointer, read on into a string, which is a JSON document of its own) and what both implementations give of it ("result", normalized), or that it is refused: then its "control", the same check of what the refusal is about given otherwise, is taken first, and "reason" is what both name, where they word it alike. "changes" are the JSON pointers of the case in which it differs from its control, "documentChanges", where a document of the run is another one, prefixes of every pointer in which that document differs. "trust" is a trust anchor and a key statement, every identity key of the anchor trusted, current or historical, at a time.',
        { run: `runs/${CHARGY}`, vectors: ids(vectors, 'verifier') });

}

/** Every object within a value a predicate holds for. */
function all(value, predicate, found = []) {
    if (Array.isArray(value))
        value.forEach(item => all(item, predicate, found));
    else if (value !== null && typeof value === 'object' && value[RAW] === undefined) {
        if (predicate(value))
            found.push(value);
        Object.values(value).forEach(item => all(item, predicate, found));
    }
    return found;
}

/** Where two values differ, as JSON pointers: into objects and arrays both are, a number by its text. */
function differences(a, b, path = '', found = []) {
    const container = (value) => value !== null && typeof value === 'object' && value[RAW] === undefined;
    if (container(a) && container(b) && Array.isArray(a) === Array.isArray(b))
        for (const key of new Set([ ...Object.keys(a), ...Object.keys(b) ]))
            differences(a[key], b[key], `${path}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`, found);
    else if (a === undefined || b === undefined || canonical(a) !== canonical(b))
        found.push(path);
    return found;
}

/** The policy identity of a trust anchor (TrustTransition.PolicyIdOf): the SHA-256 of the canonical JSON of its policy. */
function policyIdOf(qrCode) {
    const { network, holders, minConsensus, urls } = policyOfQRCode(qrCode);
    if (typeof minConsensus !== 'number')
        fail('a trust anchor without its minConsensus: PolicyIdOf of it is not known to this script');
    return sha256(utf8(canonical({ network, holders, minConsensus, urls: urls.map(url => new URL(url).href.replace(/\/+$/, '')).sort() })));
}

/** The digest of a key statement (TrustTransition.DigestOf): the SHA-256 of its content, its @context first, no signatures. */
const keyStatementDigestOf = (statement) => sha256(utf8(canonical({ '@context': CONTEXTS.keyStatement, ...without(statement, 'signatures') })));


// =====================================================================================================================
//  Write, check, mirror
// =====================================================================================================================

const frozen  = historyVectors();
anchorTheRun(frozen);

const outputs = {
    'poi-canonical-json.json':  canonicalVectors(),
    'poi-encodings.json':       encodingVectors(),
    'poi-specification.json':   specificationVectors(),
    'poi-trust.json':           trustVectors(),
    'poi-history.json':         frozen,
    'poi-refusals.json':        refusalVectors(),
    'poi-histories.json':       signedHistories(),
    'poi-qidigital.json':       qiDigitalVectors(),
    'poi-verifier.json':        verifierVectors(),
};

// The vector files, and the documents made here (chargy/), as text.
const texts = {
    ...Object.fromEntries(Object.entries(outputs).map(([ name, value ]) => [ name, serialize(value) ])),
    ...ownChargyFiles(),
};

let drift = 0;

for (const [ name, text ] of Object.entries(texts)) {

    const path = join(OUT, name);

    if (checkOnly) {
        if (!existsSync(path) || readFileSync(path, 'utf8') !== text) {
            console.error(`${name}: differs from what the generator emits - regenerate it (never edit it by hand)`);
            drift++;
        }
        continue;
    }

    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    console.log(`wrote test-vectors/${name}`);

}

// A document of chargy/ the generator no longer makes is no part of it.
for (const file of existsSync(OWN_CHARGY_DIR) ? walk(OWN_CHARGY_DIR) : []) {
    const name = relative(OUT, file).split(sep).join('/');
    if (texts[name] !== undefined)
        continue;
    if (checkOnly) {
        console.error(`${name}: the generator does not make it - regenerate (never add a file by hand)`);
        drift++;
        continue;
    }
    rmSync(file);
    console.log(`removed test-vectors/${name}`);
}

if (checkOnly) {
    if (drift > 0)
        process.exit(1);
    console.log('test-vectors: the anchors hold, every source still says what the vectors take from it, and the files are what the generator emits');
}

for (const mirror of mirrors) {
    const target = join(ROOT, mirror);
    mkdirSync(target, { recursive: true });
    for (const name of Object.keys(outputs))
        cpSync(join(OUT, name), join(target, name));
    cpSync(RUN_DIR, join(target, RUN), { recursive: true });
    cpSync(CHARGY_DIR, join(target, CHARGY), { recursive: true });
    rmSync(join(target, OWN_CHARGY), { recursive: true, force: true });
    cpSync(OWN_CHARGY_DIR, join(target, OWN_CHARGY), { recursive: true });
    console.log(`mirrored test-vectors to ${mirror}`);
}

