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

import { expect } from 'vitest';

import { etagToText, History, isArray, type JSONValue } from '../../../libs/WWCP_POI.TS/src/index.ts';

import type { DocumentStep, ReplayStep } from './vectors.ts';


/**
 * Takes one step of a replay (poi-history.json, poi-histories.json), its document given by `documentOf`, and returns the
 * history after it: throws where the history refuses it, or where the head is not the one expected.
 */
export function replayStep(current: History | undefined, step: ReplayStep, documentOf: (step: DocumentStep) => JSONValue): History {

    const now = (): History => {
        if (current === undefined)
            throw new Error('A replay starts with a snapshot!');
        return current;
    };

    switch (step.op) {

        case 'fromSnapshot':
            return History.fromSnapshot(documentOf(step));

        case 'append': {
            const commits = documentOf(step);
            for (const commit of isArray(commits) ? commits : [ commits ])
                now().append(commit);
            return now();
        }

        case 'takeCheckpoint':
            now().takeCheckpoint(documentOf(step));
            return now();

        case 'startNextEpoch': {
            const next = now().startNextEpoch();
            expect(next.root.commit.id).toBe(step.genesisCommitId);
            return next;
        }

        case 'expectHead':
            expect(now().epoch.number).toBe(step.epoch);
            expect(now().head.commit.revision).toBe(step.revision);
            expect(now().head.commit.id).toBe(step.commitId);
            if (step.eTags !== undefined)
                expect(now().head.network.eTags().map(etagToText)).toEqual(step.eTags);
            return now();

    }

}

/** Takes the steps of a replay one after the other: the history after the last one. */
export const replay = (steps: readonly ReplayStep[], documentOf: (step: DocumentStep) => JSONValue): History | undefined =>
    steps.reduce<History | undefined>((current, step) => replayStep(current, step, documentOf), undefined);
