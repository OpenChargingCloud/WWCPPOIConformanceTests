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
    canonicalJSON, ChargingStationProof, Checkpoint, CheckpointProof, Commit, etagToText, History, isArray, PriceStatement,
    RoamingNetwork, TrustAnchor, verifyChargingStation,
} from '../../../libs/WWCP_POI.TS/src/index.ts';

import { history, runDocument, runText, skipReason } from './vectors.ts';


describe(`poi-history.json: what the C# examples published (${history.run})`, () => {

    describe('versions: the ETags of their content', () => {
        for (const vector of history.versions)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {
                const network = RoamingNetwork.parse(runDocument(vector));
                expect(network.id).toBe(vector.roamingNetworkId);
                expect(network.eTags().map(etagToText)).toEqual(vector.eTags);
            });
    });

    describe('commits: their identifications, the digests of their content', () => {
        for (const vector of history.commits)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {
                const commit = Commit.parse(runDocument(vector));
                expect(commit.id).toBe(vector.commitId);
                expect(commit.roamingNetworkId).toBe(vector.roamingNetworkId);
                expect(commit.epoch).toBe(vector.epoch);
                expect(commit.revision).toBe(vector.revision);
                expect(commit.identificationHash).toBe(vector.hashAlgorithm);
                expect(commit.eTags.map(etagToText)).toEqual(vector.eTags);
            });
    });

    describe('checkpoints: their identifications', () => {
        for (const vector of history.checkpoints)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {
                const checkpoint = Checkpoint.parse(runDocument(vector));
                expect(checkpoint.id).toBe(vector.checkpointId);
                expect(checkpoint.roamingNetworkId).toBe(vector.roamingNetworkId);
                expect(checkpoint.epoch).toBe(vector.epoch);
                expect(checkpoint.sequence).toBe(vector.sequence);
                expect(checkpoint.revision).toBe(vector.revision);
                expect(checkpoint.commitId).toBe(vector.commitId);
                expect(checkpoint.isFinal).toBe(vector.final);
            });
    });

    describe('checkpoint proofs: a commit is part of a checkpoint', () => {
        for (const vector of history.checkpointProofs)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {
                const proof = CheckpointProof.parse(runDocument(vector));
                expect(proof.checkpointId).toBe(vector.checkpointId);
                expect(proof.commitId).toBe(vector.commitId);
                proof.verify(Checkpoint.parse(runDocument(vector.checkpoint)));
            });
    });

    describe('price statements: their digests', () => {
        for (const vector of history.priceStatements)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {
                const statement = PriceStatement.parse(runDocument(vector));
                expect(statement.sequence).toBe(vector.sequence);
                expect(statement.digestHex()).toBe(vector.digest);
                expect(statement.previous).toBe(vector.previous);
            });
    });

    describe('trust anchors: the text of their QR codes', () => {
        for (const vector of history.trustAnchors)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {
                const text   = runText(vector.file).trim();
                const anchor = TrustAnchor.parse(text);
                expect(anchor.id).toBe(vector.roamingNetworkId);
                expect(anchor.urls).toEqual(vector.urls);
                expect(anchor.keys).toEqual(vector.keys);
                expect(anchor.minConsensus).toBe(vector.minConsensus);
                expect(canonicalJSON(anchor.toJSON())).toBe(vector.json);
                expect(anchor.toQRCode()).toBe(text);
            });
    });

    describe('station proofs: their roots, verified against the trust anchor', () => {
        for (const vector of history.stationProofs)
            it.skipIf(skipReason(vector) !== undefined)(vector.id, () => {

                const proof   = ChargingStationProof.parse(runDocument(vector));
                const anchor  = TrustAnchor.parse(runText(vector.trustAnchor));

                expect(etagToText(proof.calculate().eTag)).toBe(vector.root);
                expect(proof.commitId).toBe(vector.commitId);
                expect(proof.revision).toBe(vector.revision);

                proof.verify(anchor, vector.at);

                for (const station of vector.chargingStations)
                    for (const evseId of station.evseIds) {
                        const verified = verifyChargingStation(anchor, proof, { at: vector.at, evseId });
                        if (station.chargingStationId !== null)
                            expect(verified.chargingStation['@id']).toBe(station.chargingStationId);
                    }

            });
    });

    describe('replays: the history commit by commit', () => {
        for (const vector of history.replays)
            it.skipIf(skipReason(vector) !== undefined)(`${vector.id}: ${vector.description}`, () => {

                // The replay checks the content; who may sign commits and checkpoints is the verifier's business, not its.
                expect(vector.commitAndCheckpointSignatures).toBe('unchecked');

                let current: History | undefined;
                const now = (): History => { if (current === undefined) throw new Error('The replay starts with a snapshot!'); return current; };

                for (const step of vector.steps) {
                    switch (step.op) {

                        case 'fromSnapshot':
                            current = History.fromSnapshot(runDocument(step.file));
                            break;

                        case 'append': {
                            const commits = runDocument(step.file);
                            for (const commit of isArray(commits) ? commits : [ commits ])
                                now().append(commit);
                            break;
                        }

                        case 'takeCheckpoint':
                            now().takeCheckpoint(runDocument(step.file));
                            break;

                        case 'startNextEpoch':
                            current = now().startNextEpoch();
                            expect(current.root.commit.id).toBe(step.genesisCommitId);
                            break;

                        case 'expectHead':
                            expect(now().epoch.number).toBe(step.epoch);
                            expect(now().head.commit.revision).toBe(step.revision);
                            expect(now().head.commit.id).toBe(step.commitId);
                            if (step.eTags !== undefined)
                                expect(now().head.network.eTags().map(etagToText)).toEqual(step.eTags);
                            break;

                    }
                }

            });
    });

});
