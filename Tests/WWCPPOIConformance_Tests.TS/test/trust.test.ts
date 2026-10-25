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

import { ChargingStationProof, etagToText, parseJSON, parseJSONObject, TrustAnchor, verifyChargingStation } from '../../../libs/WWCP_POI.TS/src/index.ts';

import { deviates, skipReason, trust } from './vectors.ts';


describe('poi-trust.json: station proofs of the example network, against a trust anchor', () => {

    for (const vector of trust.stationProofs) {
        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.expected}): ${vector.description}`, () => {

            const proof   = parseJSONObject(vector.proof);
            const anchor  = TrustAnchor.fromJSON(parseJSON(vector.trustAnchor));
            const verify  = (): unknown => verifyChargingStation(anchor, proof, { at: vector.at, evseId: vector.evseId });

            // The root the proof leads to, whatever its attestations: also a proof refused for one of them, e.g. one without
            // a validUntil, leads to it.
            expect(etagToText(ChargingStationProof.parse({ ...proof, attestations: [] }).calculate().eTag)).toBe(vector.root);

            // A known deviation is pinned: the day it is gone, this turns red and the marker is removed in the generator.
            if ((vector.expected === 'accepted') !== deviates(vector))
                verify();
            else
                expect(verify).toThrow();

        });
    }

});
