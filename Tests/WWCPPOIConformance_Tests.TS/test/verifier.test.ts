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

import { results, verifier } from './verifier.ts';
import { skipReason } from './vectors.ts';


describe('poi-verifier.json: the verifier extensions of WWCP_POI.TS 0.2.0, of the fixtures of ChargyWebApp', () => {

    for (const vector of verifier.vectors) {

        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.expected}): ${vector.description}`, () => {

            if (vector.expected === 'accepted') {
                expect(results(vector.kind, vector)).toEqual(vector.result);
                return;
            }

            if (vector.control === undefined)
                throw new Error(`The refusal ${vector.id} names no control`);

            // The control: the same check, of what the vector is about given otherwise, taken.
            results(vector.kind, vector.control);

            // Refused for what the vector is about, where it names it.
            if (vector.reason === undefined)
                expect(() => results(vector.kind, vector)).toThrow();
            else
                expect(() => results(vector.kind, vector)).toThrow(vector.reason);

        });

    }

});
