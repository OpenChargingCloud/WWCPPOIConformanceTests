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
 *   - libs/WWCP_POI/SPECIFICATION.md, sections 1 and 6: the examples of the specification;
 *   - test-vectors/runs/<run>/: what one run of the C# examples A1 to A13 of WWCP_POI published, frozen.
 *
 * Every value is taken VERBATIM from its source, and this script refuses to write when a source no longer says it
 * (drift guard). Before writing anything it re-derives the anchors with nothing but node:crypto - the SHA-256 and
 * SHA-512 identifications, ETags of canonical JSON, tree digests, key thumbprints and Ed25519 signatures of section 6,
 * the digests that chain the price statements of the run - and refuses to write when even one mismatches: an
 * independent third look, next to the two harnesses, at what the vectors claim.
 *
 *   node tools/generate-test-vectors.mjs                  writes test-vectors/poi-*.json
 *   node tools/generate-test-vectors.mjs --check          fails when the committed files differ (the CI drift guard)
 *   node tools/generate-test-vectors.mjs --mirror <dir>   also refreshes a vendored copy, e.g. libs/WWCP_POI.TS/tests/vectors
 *
 * Never edit the JSON files by hand: edit this script and run it again.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';


const ROOT         = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT          = join(ROOT, 'test-vectors');
const RUN          = 'csharp-987fa26';
const RUN_DIR      = join(OUT, 'runs', RUN);

/** A point in time while the key statements, the keys and the attestations of the frozen run are valid. */
const AT           = '2026-10-26T00:58:00.000Z';

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
    const implementations = DEVIATIONS[name] ?? fail(`no deviation ${name}`);
    return { knownDeviations: implementations, deviation: `docs/implementation-deviations.md#${name.toLowerCase()}` };
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


// ---- Base45 (RFC 9285) and the CBOR this script needs to read: trust anchors ------------------------------------------

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
        else if (info  >  26) fail('CBOR of a trust anchor: no 64 bit lengths or indefinite lengths expected');
        switch (major) {
            case 0: return length;
            case 1: return -1 - length;
            case 2: { const value = bytes.subarray(offset, offset + length); offset += length; return value; }
            case 3: { const value = bytes.subarray(offset, offset + length).toString('utf8'); offset += length; return value; }
            case 4: return Array.from({ length }, read);
            case 5: { const map = {}; for (let i = 0; i < length; i++) { const key = read(); map[key] = read(); } return map; }
            default: fail(`CBOR of a trust anchor: major type ${major} not expected`);
        }
    };
    const value = read();
    if (offset !== bytes.length)
        fail('CBOR of a trust anchor: bytes after the data item');
    return value;
}


// ---- Canonical JSON, as far as the anchors need it --------------------------------------------------------------------
//
// Numbers stay the text they are written as (JSON.parse with the source text of its values): the C# implementation
// writes them canonically already. Strings are written as Styx writes them for what the frozen run holds; anything this
// script does not know how Styx writes it is refused, never guessed.

const RAW = Symbol('raw number');

const parseRaw = (text) => JSON.parse(text, (_key, value, context) => typeof value === 'number' ? { [RAW]: context.source } : value);

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
        if (/[eE+]/.test(value[RAW]) || value[RAW].startsWith('-0'))
            fail(`canonical JSON of the number ${value[RAW]}: not written canonically`);
        return value[RAW];
    }
    return '{' + Object.keys(value).sort().map(key => canonicalString(key) + ':' + canonical(value[key])).join(',') + '}';
}


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
        'WWCP POI 3 SPECIFICATION.md, section 6 (libs/WWCP_POI/SPECIFICATION.md)',
        'The examples of the specification, every value as written there: the content of a version, its ETags and its effective tree, identifications, keys, signatures, a price statement and a trust anchor.',
        {
            contents:          [ { id: 'spec-6-content', description: 'The content of the example version, its canonical JSON, and its ETags (2, 3, 8.2).', content, eTags } ],
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
    const head   = jsonRun('published/QA-commit.json');
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
            { op: 'expectHead',      epoch: 2, revision: head.revision, commitId: head['@id'], eTags: head.eTags.map((eTag, index) => etagText(eTag, `QA-commit.json/eTags/${index}`)) },
        ],
    } ];

    for (const [ name, list ] of Object.entries({ versions, commits, checkpoints, checkpointProofs, priceStatements, trustAnchors, stationProofs }))
        ids(list, `history (${name})`);

    return vectorFile(
        `WWCP POI 3 (libs/WWCP_POI), as its C# examples A1 to A13 published it in one run: test-vectors/runs/${RUN}`,
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

    // ---- Change sets (4, 5.2): identified by their content, naming only what they were rebased from, with changes
    //      (csharp-review 4). The commit of each is identified anew, so that only its change set is refused.
    const without     = (object, ...properties) => Object.fromEntries(Object.entries(object).filter(([ property ]) => !properties.includes(property)));
    const contentId   = (changeSet) => sha256(utf8(canonical({ ...without(changeSet, '@id', 'signatures'), '@context': 'https://open.charging.cloud/contexts/wwcp/roamingNetwork/changeSet/v3' })));
    const commitIdOf  = (commit)    => (commit['@id'].length === 128 ? sha512 : sha256)(utf8(canonical({ ...without(commit, '@id', 'signatures', 'changeSet'),
                                                                                                         '@context':  'https://open.charging.cloud/contexts/wwcp/roamingNetwork/commit/v3',
                                                                                                         changeSet:   without(commit.changeSet, 'signatures', '@context') })));

    const commitN     = parseRaw(readRun('published/QA-commit.json'));
    const otherN      = parseRaw(readRun('published/QA-commits-since-genesis.json'))[0].changeSet;

    if (contentId(commitN.changeSet) !== commitN.changeSet['@id'] || contentId(otherN) !== otherN['@id'] || commitIdOf(commitN) !== commitN['@id'])
        fail('the change sets and the commit of the run are not identified as this script identifies them');

    // The change set changed as given, identified anew by its content unless it names its @id, and its commit identified anew.
    const changeSetPatch = (changes, changeSetId) => {
        const changeSet = { ...commitN.changeSet, ...changes };
        const id        = changeSetId ?? contentId(changeSet);
        return [ ...Object.entries(changes).map(([ property, value ]) => ({ op: property in commitN.changeSet ? 'replace' : 'add', path: `/changeSet/${property}`, value })),
                 { op: 'replace', path: '/changeSet/@id', value: id },
                 { op: 'replace', path: '/@id',           value: commitIdOf({ ...commitN, changeSet: { ...changeSet, '@id': id } }) } ];
    };

    refuse({ id: 'changeSet-id',              kind: 'commit', basis: `${SPEC}, 4, 5.2`, description: 'The change set of a commit has the @id of another change set of the run, its commit identified anew: a change set is identified by its content, nobody names another one with its @id (csharp-review 4).', document: patched('published/QA-commit.json', '', changeSetPatch({}, otherN['@id'])) });
    refuse({ id: 'changeSet-rebasedFrom',     kind: 'commit', basis: `${SPEC}, 4, 5.2`, description: 'The change set of a commit names another change set of the run, with its ETags, as the one it was rebased from, identified anew by its content: it was not rebased from it (csharp-review 4).', document: patched('published/QA-commit.json', '', changeSetPatch({ metadata: { rebasedFrom: [ { '@id': otherN['@id'], beforeETags: otherN.beforeETags, afterETags: otherN.afterETags } ] } })) });
    refuse({ id: 'changeSet-without-changes', kind: 'commit', basis: `${SPEC}, 4, 5.2`, description: 'The change set of a commit with one parent without changes, identified anew by its content: it would change nothing.', document: patched('published/QA-commit.json', '', changeSetPatch({ changes: [] })) });
    refuse({ id: 'changeSet-merge-id',        kind: 'commit', basis: `${SPEC}, 4, 5.2, 5.3`, description: 'The change set of a commit with one parent named as the change set of a merge, which only a merge commit has.', document: patched('published/QA-commit.json', '', changeSetPatch({}, 'merge-' + '0'.repeat(32))) });

    // Rebased with a change naming no old value: only old values tell that a change set committed meanwhile changed what it
    // changes, which the rebase would have overwritten (csharp-review 12). It names the change set it was rebased from
    // rightly, with the ETags of another change set of the run, so that only the missing old value is refused.
    if (!commitN.changeSet.changes.some(change => 'oldValue' in change && change.kind !== 'Add' && change.kind !== 'AddElement'))
        fail('published/QA-commit.json: no change of its change set names an old value');

    const withoutOldValues = commitN.changeSet.changes.map(change => without(change, 'oldValue'));
    const rebasedOriginal  = { ...commitN.changeSet, changes: withoutOldValues, beforeETags: otherN.beforeETags, afterETags: otherN.afterETags };

    refuse({ id: 'changeSet-rebased-without-old-value', kind: 'commit', basis: `${SPEC}, 4; csharp-review 12`, reason: 'which was rebased, has no old value',
             description: 'The change set of a commit without the old value of its change, naming the change set it was rebased from rightly, identified anew: a rebase without old values may have overwritten a concurrent change.',
             document: patched('published/QA-commit.json', '', changeSetPatch({ changes: withoutOldValues, metadata: { rebasedFrom: [ { '@id': contentId(rebasedOriginal), beforeETags: otherN.beforeETags, afterETags: otherN.afterETags } ] } })) });

    // ---- Checkpoints (10.1): their @id is the digest of their content.
    refuse({ id: 'checkpoint-sequence',       kind: 'checkpoint', basis: `${SPEC}, 10.1`, description: 'Another sequence.',                                                                            document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/sequence', value: 2 } ]) });
    refuse({ id: 'checkpoint-previous',       kind: 'checkpoint', basis: `${SPEC}, 10.1`, description: 'Another previous checkpoint.',                                                                 document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/previousId', value: '0'.repeat(64) } ]) });
    refuse({ id: 'checkpoint-commits-root',   kind: 'checkpoint', basis: `${SPEC}, 10.1`, description: 'Another root of its commits.',                                                                 document: patched('published/QA-checkpoint-1.json', '', [ { op: 'replace', path: '/commits/@merkleRoot', value: '0'.repeat(64) } ]) });
    refuse({ id: 'checkpoint-epoch',          kind: 'checkpoint', basis: `${SPEC}, 10.1, 11`, description: 'A checkpoint of epoch 1 without "epoch": its @id is calculated with it (csharp-review 11).', document: patched('published/QA-checkpoint-1.json', '', [ { op: 'remove', path: '/epoch' } ]) });

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
    has([ release ],                         'chargy-1.5.0');
    has(ptb.certificates,                     'PTB-2026-0042');

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

    twice('version-twice-release',               'libs/WWCP_POI/docs/TransparencySoftwareManufacturer.md',
          'Another transparency software manufacturer has a release of the identification of the one of GraphDefined, in uppercase.',
          "The transparency software release 'CHARGY-1.5.0' of the manufacturer 'OpenChargingCloud' is one of the manufacturer 'GraphDefined' already",
          [ { op: 'add', path: '/transparencySoftwareManufacturers/-', value: { '@id': 'OpenChargingCloud', name: { en: 'Open Charging Cloud' }, transparencySoftware: [ { ...release, '@id': 'CHARGY-1.5.0' } ], created, lastChange: created } } ]);

    twice('version-twice-certificate',           'libs/WWCP_POI/docs/ConformityAssessmentBody.md',
          'Another conformity assessment body has a certificate of the identification of the one of PTB, in lowercase.',
          "The certificate 'ptb-2026-0042' of the conformity assessment body 'VDE' is one of the conformity assessment body 'PTB' already",
          [ { op: 'add', path: '/conformityAssessmentBodies/-', value: { '@id': 'VDE', name: { de: 'VDE Prüf- und Zertifizierungsinstitut' }, notifiedFor: [ 'MID' ],
                                                                        certificates: [ { ...ptb.certificates.find(certificate => certificate['@id'] === 'PTB-2026-0042'), '@id': 'ptb-2026-0042' } ], created, lastChange: created } } ]);

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
    const ptb0017   = named('/conformityAssessmentBodies/1/certificates/0',                  'PTB-2026-0017');
    const ptb0042   = named('/conformityAssessmentBodies/1/certificates/1',                  'PTB-2026-0042');
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
             'The certificate PTB-2026-0017 names a further hardware revision with a space before it: it names hardware revisions of its model, none of which begins with whitespace.',
             "hardwareRevisions[1]: Invalid text representation of a hardware revision: ' 2.1'!",
             [ { op: 'add', path: `${ptb0017}/hardwareRevisions/-`, value: ' 2.1' } ]);

    withText('version-text-certificate-energy-meter',       `${DOCS}/ConformityAssessmentBody.md, ${DOCS}/EnergyMeterManufacturer.md`,
             'The energy meter the certificate PTB-2026-0042 was issued with names its firmware version followed by a no-break space (U+00A0).',
             "energyMeters[0]: firmwareVersions[0]: Invalid text representation of a firmware version: '3.2 '!",
             [ { op: 'replace', path: `${ptb0042}/energyMeters/0/firmwareVersions/0`, value: '3.2 ' } ]);

    withText('version-text-certificate-twice',              `${DOCS}/ConformityAssessmentBody.md`,
             'The certificate PTB-2026-0017 names the hardware revision 2.1 twice.',
             "A hardware revision of the certificate 'PTB-2026-0017' must not be given twice!",
             [ { op: 'add', path: `${ptb0017}/hardwareRevisions/-`, value: '2.1' } ]);

    withText('version-text-certificate-energy-meter-twice', `${DOCS}/ConformityAssessmentBody.md`,
             'The energy meter the certificate PTB-2026-0042 was issued with names the hardware revision 2.1 twice.',
             "A hardware revision of the certified energy meter model 'KDM-500' of 'KERNBERG' must not be given twice!",
             [ { op: 'add', path: `${ptb0042}/energyMeters/0/hardwareRevisions/-`, value: '2.1' } ]);

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
//  Write, check, mirror
// =====================================================================================================================

const outputs = {
    'poi-canonical-json.json':  canonicalVectors(),
    'poi-encodings.json':       encodingVectors(),
    'poi-specification.json':   specificationVectors(),
    'poi-trust.json':           trustVectors(),
    'poi-history.json':         historyVectors(),
    'poi-refusals.json':        refusalVectors(),
};

let drift = 0;

for (const [ name, value ] of Object.entries(outputs)) {

    const path = join(OUT, name);
    const text = serialize(value);

    if (checkOnly) {
        if (!existsSync(path) || readFileSync(path, 'utf8') !== text) {
            console.error(`${name}: differs from what the generator emits - regenerate it (never edit it by hand)`);
            drift++;
        }
        continue;
    }

    mkdirSync(OUT, { recursive: true });
    writeFileSync(path, text);
    console.log(`wrote test-vectors/${name}`);

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
    console.log(`mirrored test-vectors to ${mirror}`);
}

