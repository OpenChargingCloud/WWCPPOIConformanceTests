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

import { replay, replayStep } from './replay.ts';
import { deviates, histories, historyDocument, skipReason, type ReplayStep } from './vectors.ts';


describe('poi-histories.json: histories the generator signed, what they take and refuse', () => {

    for (const vector of histories.replays) {

        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.expected}): ${vector.description}`, () => {

            // The replay checks the content; who may sign commits and checkpoints is the verifier's business, not its.
            expect(vector.commitAndCheckpointSignatures).toBe('unchecked');

            const documentOf = (step: { document?: string }) => historyDocument(vector.history, step.document);

            if (vector.expected === 'accepted') {
                replay(vector.steps, documentOf);
                return;
            }

            const before  = vector.steps.slice(0, -1);
            const last    = vector.steps.at(-1);

            if (last === undefined || vector.control === undefined)
                throw new Error(`The refusal ${vector.id} names no step to refuse, or no control`);

            // The control: in place of the refused document, the one refused but for what the replay is about is taken.
            replay([ ...before, { ...last, document: vector.control } as ReplayStep ], documentOf);

            const current = replay(before, documentOf);

            if (deviates(vector)) {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                replayStep(current, last, documentOf);
                return;
            }

            // Refused for what the vector is about, where it names it.
            if (vector.reason === undefined)
                expect(() => replayStep(current, last, documentOf)).toThrow();
            else
                expect(() => replayStep(current, last, documentOf)).toThrow(vector.reason);

        });

    }

});
