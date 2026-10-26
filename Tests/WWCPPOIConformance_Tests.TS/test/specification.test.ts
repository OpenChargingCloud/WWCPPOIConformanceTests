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
    canonicalJSON, canonicalJSONBytes, Commit, etagToText, hash, parseJSON, parseJSONObject, POIPublicKey, PriceStatement,
    RoamingNetwork, toHex, TrustAnchor, verifySignature, type HashAlgorithm,
} from '../../../libs/WWCP_POI.TS/src/index.ts';

import { skipReason, specification, type PublicKeyOf } from './vectors.ts';


const keyOf = (vector: PublicKeyOf): POIPublicKey =>
    POIPublicKey.parse({ '@id': vector.keyId, key: vector.coseKey });

const utf8 = (text: string): Uint8Array =>
    new TextEncoder().encode(text);


describe('poi-specification.json: the examples of SPECIFICATION.md, section 6, and custom data (section 2)', () => {

    for (const vector of specification.contents)
        it(`${vector.id}: ${vector.description}`, () => {
            const content = parseJSONObject(vector.content);
            const network = RoamingNetwork.parse(content);
            expect(canonicalJSON(content)).toBe(vector.content);
            // The content as the version holds it: custom data as given (section 2).
            expect(canonicalJSON(network.content)).toBe(vector.content);
            expect(network.eTags().map(etagToText)).toEqual(vector.eTags);
        });

    for (const vector of specification.skeletons)
        it(`${vector.id}: ${vector.description}`, () => {
            const skeleton = parseJSONObject(vector.skeleton);
            expect(canonicalJSON(skeleton)).toBe(vector.skeleton);
            expect(toHex(hash(vector.hashAlgorithm as HashAlgorithm, Uint8Array.of(0x00, ...canonicalJSONBytes(skeleton))))).toBe(vector.digest);
        });

    for (const vector of specification.commits)
        it(`${vector.id}: ${vector.description}`, () => {
            const commit = Commit.parse(parseJSON(JSON.stringify(vector.commit)));
            expect(commit.id).toBe(vector.commitId);
            expect(commit.identificationHash).toBe(vector.hashAlgorithm);
            expect(canonicalJSON(commit.identificationContent())).toBe(vector.content);
        });

    for (const vector of specification.keys)
        it(`${vector.id}: ${vector.description}`, () => {
            expect(POIPublicKey.parse({ '@id': vector.keyId, key: vector.coseKey }).id).toBe(vector.keyId);
            expect(() => POIPublicKey.parse({ '@id': '0'.repeat(64), key: vector.coseKey })).toThrow();
        });

    for (const vector of specification.signatures)
        it(`${vector.id}: ${vector.description}`, () => {
            expect(canonicalJSON(parseJSONObject(vector.input))).toBe(vector.input);
            verifySignature(vector.algorithm, keyOf(vector).key, utf8(vector.input), vector.value);
        });

    for (const vector of specification.signatures)
        it.skipIf(skipReason({ requires: [ 'signing' ] }) !== undefined)(`${vector.id} (signing): the same value of the private seed`, () => {
            throw new Error('WWCP_POI.TS signs nothing');
        });

    for (const vector of specification.invalidSignatures)
        it(`${vector.id}: ${vector.description}`, () => {
            expect(() => { verifySignature(vector.algorithm, keyOf(vector).key, utf8(vector.input), vector.value); }).toThrow();
        });

    for (const vector of specification.priceStatements)
        it(`${vector.id}: ${vector.description}`, () => {
            expect(PriceStatement.parse(parseJSON(vector.statement)).digestHex()).toBe(vector.digest);
        });

    for (const vector of specification.trustAnchors)
        it.skipIf(skipReason(vector) !== undefined)(`${vector.id}: ${vector.description}`, () => {

            const anchor = TrustAnchor.parse(vector.qrCode);

            expect(anchor.id).toBe(vector.roamingNetworkId);
            expect(anchor.urls).toEqual(vector.urls);
            expect(anchor.keys).toEqual(vector.keys);
            expect(anchor.minConsensus).toBe(vector.minConsensus);
            expect(canonicalJSON(anchor.toJSON())).toBe(canonicalJSON(parseJSON(vector.json)));
            expect(anchor.toQRCode()).toBe(vector.qrCode);
            expect(TrustAnchor.fromJSON(parseJSON(vector.json)).toQRCode()).toBe(vector.qrCode);

        });

});
