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

import {
    ChargingStationProof, Checkpoint, CheckpointProof, Commit, POIPublicKey, PriceStatement, RoamingNetwork, TrustAnchor,
    type JSONValue,
} from '../../../libs/WWCP_POI.TS/src/index.ts';

import { deviates, patched, refusals, runDocument, runText, skipReason, type RefusalVector } from './vectors.ts';


/** What a vector of its kind checks, of the given document: throws when it is refused. */
function check(vector: RefusalVector, document: JSONValue | undefined): void {

    const need = <T>(value: T | undefined, what: string): T => {
        if (value === undefined)
            throw new Error(`The vector ${vector.id} names no ${what}!`);
        return value;
    };

    switch (vector.kind) {

        case 'commit':
            Commit.parse(document);
            return;

        case 'checkpoint':
            Checkpoint.parse(document);
            return;

        case 'version':
            RoamingNetwork.parse(document);
            return;

        case 'checkpointProof':
            CheckpointProof.parse(document).verify(Checkpoint.parse(runDocument(need(vector.checkpoint, 'checkpoint'))));
            return;

        case 'stationProof':
            ChargingStationProof.parse(document).verify(TrustAnchor.parse(runText(need(vector.trustAnchor, 'trust anchor'))), need(vector.at, 'time'));
            return;

        case 'priceStatement': {
            const statement = PriceStatement.parse(document);
            const network   = RoamingNetwork.parse(runDocument(need(vector.keysFrom, 'version with the keys')));
            const operator  = need(network.chargingStationOperator(statement.signer), `charging station operator '${statement.signer}'`);
            statement.verify(network.id, statement.signer, POIPublicKey.parseAll(operator['signingKeys'], 'signing keys'));
            return;
        }

        case 'trustAnchor':
            TrustAnchor.parse(need(vector.text, 'text'));
            return;

    }

}


describe(`poi-refusals.json: what an implementation must refuse`, () => {

    for (const vector of refusals.vectors) {

        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.kind}): ${vector.description}`, () => {

            const document = vector.document === undefined ? undefined : patched(vector.document);

            // The control: the document as published passes the same check, so the refusal is the patch's doing.
            if (vector.document !== undefined && vector.document.patch.length > 0)
                check(vector, runDocument(vector.document));

            if (deviates(vector)) {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                check(vector, document);
                return;
            }

            // Refused for what the vector is about, where it names it.
            if (vector.reason === undefined)
                expect(() => { check(vector, document); }).toThrow();
            else
                expect(() => { check(vector, document); }).toThrow(vector.reason);

        });

    }

});
