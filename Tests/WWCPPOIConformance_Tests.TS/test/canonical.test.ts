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

import { describe, expect, it } from 'vitest';

import { canonicalJSON, deterministicCbor, fromBase45, fromBase64, parseJSON, toBase45, toHex } from '../../../libs/WWCP_POI.TS/src/index.ts';

import { canonical, deviates, encodings, skipReason } from './vectors.ts';


describe('poi-canonical-json.json: canonical JSON and deterministic CBOR', () => {

    for (const vector of canonical.vectors) {
        it.skipIf(skipReason(vector) !== undefined)(`${vector.id}: ${vector.description}`, () => {

            const value = parseJSON(vector.input);

            expect(canonicalJSON(value)).toBe(vector.expected.canonical);

            if (vector.expected.cborHex !== undefined)
                expect(toHex(deterministicCbor(value))).toBe(vector.expected.cborHex);

        });
    }

    for (const vector of canonical.invalidInputs) {
        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.expectedError}): ${vector.description}`, () => {

            if (deviates(vector)) {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                expect(() => parseJSON(vector.input)).not.toThrow();
                return;
            }

            expect(() => parseJSON(vector.input)).toThrow();

        });
    }

});


describe('poi-encodings.json: Base64 and Base45', () => {

    for (const vector of encodings.base64)
        it(`${vector.id}: ${vector.description}`, () => { expect(toHex(fromBase64(vector.text))).toBe(vector.hex); });

    for (const vector of encodings.base64Invalid)
        it(`${vector.id}: ${vector.description}`, () => { expect(() => fromBase64(vector.text)).toThrow(); });

    for (const vector of encodings.base45)
        it(`${vector.id}: ${vector.description}`, () => {
            expect(toHex(fromBase45(vector.text))).toBe(vector.hex);
            expect(toBase45(Uint8Array.from(Buffer.from(vector.hex, 'hex')))).toBe(vector.text);
        });

    for (const vector of encodings.base45Invalid)
        it(`${vector.id}: ${vector.description}`, () => { expect(() => fromBase45(vector.text)).toThrow(); });

});
