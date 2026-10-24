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

import { readFileSync } from 'node:fs';

import { clone, isArray, isObject, parseJSON, type JSONValue } from '../../../libs/WWCP_POI.TS/src/index.ts';


/**
 * The name this harness (and its implementation under test) is known by within the vector files
 * ("knownDeviations", "notApplicable").
 */
export const IMPLEMENTATION_NAME = 'wwcp-poi.ts';

/**
 * The optional capabilities WWCP_POI.TS provides ("requires" of vectors). It verifies, it does not sign: vectors that
 * ask an implementation to produce a signature are the C# implementation's.
 */
export const CAPABILITIES: ReadonlySet<string> = new Set([]);

/**
 * Every capability name the vector format knows. A vector requiring anything else means the vector files are newer
 * than this harness: fail, never skip silently.
 */
export const KNOWN_CAPABILITIES: ReadonlySet<string> = new Set([
    'signing',
]);


const VECTORS = new URL('../../../test-vectors/', import.meta.url);

function load<T>(fileName: string): T {
    return JSON.parse(readFileSync(new URL(fileName, VECTORS), 'utf8')) as T;
}


// ---- What every vector may say about who it applies to ---------------------------------------------------------------

export interface Applicability {
    readonly knownDeviations?:  readonly string[];
    readonly notApplicable?:    readonly string[];
    readonly requires?:         readonly string[];
}

/** Whether this implementation is known to deviate from the vector: it is then held to its deviation, not the vector. */
export const deviates = (vector: Applicability): boolean =>
    vector.knownDeviations?.includes(IMPLEMENTATION_NAME) ?? false;

/** Why this harness skips a vector, or undefined when it runs it. */
export function skipReason(vector: Applicability): string | undefined {

    for (const capability of vector.requires ?? [])
        if (!KNOWN_CAPABILITIES.has(capability))
            throw new Error(`The vector requires the capability '${capability}' this harness does not know: the vector files are newer than the harness!`);

    const missing = (vector.requires ?? []).filter(capability => !CAPABILITIES.has(capability));

    if (missing.length > 0)
        return `requires ${missing.join(', ')}, which ${IMPLEMENTATION_NAME} does not provide`;

    if (vector.notApplicable?.includes(IMPLEMENTATION_NAME))
        return `not applicable to ${IMPLEMENTATION_NAME}`;

    return undefined;

}


// ---- poi-canonical-json.json -------------------------------------------------------------------------------------

export interface CanonicalVector extends Applicability {
    readonly id:           string;
    readonly description:  string;
    readonly input:        string;
    readonly expected:     { readonly canonical: string, readonly cborHex?: string };
}

export interface InvalidJSONVector extends Applicability {
    readonly id:             string;
    readonly description:    string;
    readonly input:          string;
    readonly expectedError:  string;
}

export const canonical = load<{ vectors: CanonicalVector[], invalidInputs: InvalidJSONVector[] }>('poi-canonical-json.json');


// ---- poi-encodings.json -------------------------------------------------------------------------------------------

export interface EncodingVector       extends Applicability { readonly id: string, readonly description: string, readonly text: string, readonly hex: string }
export interface InvalidEncodingVector extends Applicability { readonly id: string, readonly description: string, readonly text: string }

export const encodings = load<{ base64: EncodingVector[], base64Invalid: InvalidEncodingVector[], base45: EncodingVector[], base45Invalid: InvalidEncodingVector[] }>('poi-encodings.json');


// ---- poi-specification.json -----------------------------------------------------------------------------------------

export interface PublicKeyOf { readonly coseKey: string, readonly keyId: string, readonly rawPublicKey: string }

export interface SpecificationVectors {
    readonly contents:           ReadonlyArray<Applicability & { id: string, description: string, content: string, eTags: string[] }>;
    readonly skeletons:          ReadonlyArray<Applicability & { id: string, description: string, skeleton: string, hashAlgorithm: string, digest: string }>;
    readonly commits:            ReadonlyArray<Applicability & { id: string, description: string, commit: JSONValue, content: string, hashAlgorithm: string, commitId: string }>;
    readonly keys:               ReadonlyArray<Applicability & { id: string, description: string, coseKey: string, keyId: string, algorithm: string, rawPublicKey: string }>;
    readonly signatures:         ReadonlyArray<Applicability & PublicKeyOf & { id: string, description: string, algorithm: string, privateSeed: string, input: string, value: string }>;
    readonly invalidSignatures:  ReadonlyArray<Applicability & PublicKeyOf & { id: string, description: string, algorithm: string, input: string, value: string }>;
    readonly priceStatements:    ReadonlyArray<Applicability & { id: string, description: string, statement: string, digest: string }>;
    readonly trustAnchors:       ReadonlyArray<Applicability & { id: string, description: string, json: string, qrCode: string, roamingNetworkId: string, urls: string[], keys: string[], minConsensus: number }>;
}

export const specification = load<SpecificationVectors>('poi-specification.json');


// ---- poi-trust.json ---------------------------------------------------------------------------------------------

export interface TrustVector extends Applicability {
    readonly id:           string;
    readonly description:  string;
    readonly basis:        string;
    readonly expected:     'accepted' | 'refused';
    /** JSON text of the trust anchor and the proof, read as POI reads JSON. */
    readonly trustAnchor:  string;
    readonly proof:        string;
    readonly at:           string;
    readonly evseId:       string;
    readonly root:         string;
}

export const trust = load<{ stationProofs: TrustVector[] }>('poi-trust.json');


// ---- poi-history.json -------------------------------------------------------------------------------------------

/** A document of the frozen run: a file and a JSON pointer (RFC 6901) into it, "" for the whole file. */
export interface DocumentRef { readonly file: string, readonly pointer: string }

export interface HistoryVectors {
    readonly run:               string;
    readonly at:                string;
    readonly versions:          ReadonlyArray<Applicability & DocumentRef & { id: string, roamingNetworkId: string, commitId?: string, epoch?: number, revision?: number, eTags: string[] }>;
    readonly commits:           ReadonlyArray<Applicability & DocumentRef & { id: string, commitId: string, roamingNetworkId: string, epoch: number, revision: number, hashAlgorithm: string, eTags: string[] }>;
    readonly checkpoints:       ReadonlyArray<Applicability & DocumentRef & { id: string, checkpointId: string, roamingNetworkId: string, epoch: number, sequence: number, revision: number, commitId: string, final: boolean }>;
    readonly checkpointProofs:  ReadonlyArray<Applicability & DocumentRef & { id: string, checkpoint: DocumentRef, checkpointId: string, commitId: string, revision: number, index: number, size: number }>;
    readonly priceStatements:   ReadonlyArray<Applicability & DocumentRef & { id: string, roamingNetworkId: string, entityType: string, entityId: string, sequence: number, algorithm: string, keyId: string, digest: string, previous?: string }>;
    readonly trustAnchors:      ReadonlyArray<Applicability & { id: string, file: string, roamingNetworkId: string, urls: string[], keys: string[], minConsensus: number, json: string }>;
    readonly stationProofs:     ReadonlyArray<Applicability & DocumentRef & { id: string, trustAnchor: string, at: string, commitId: string, revision: number, hashAlgorithm: string, root: string, chargingStations: Array<{ chargingStationId: string | null, evseIds: string[] }>, expected: 'accepted' }>;
    readonly replays:           ReadonlyArray<Applicability & { id: string, description: string, commitAndCheckpointSignatures: 'unchecked', steps: ReplayStep[] }>;
}

export type ReplayStep =
    | { op: 'fromSnapshot',    file: string }
    | { op: 'append',          file: string }
    | { op: 'takeCheckpoint',  file: string }
    | { op: 'startNextEpoch',  genesisCommitId: string }
    | { op: 'expectHead',      epoch: number, revision: number, commitId: string, eTags?: string[] };

export const history = load<HistoryVectors>('poi-history.json');


// ---- poi-refusals.json ------------------------------------------------------------------------------------------

export interface PatchOperation { readonly op: 'add' | 'replace' | 'remove', readonly path: string, readonly value?: unknown }

export interface RefusalVector extends Applicability {
    readonly id:           string;
    readonly kind:         'commit' | 'checkpoint' | 'version' | 'checkpointProof' | 'stationProof' | 'priceStatement' | 'trustAnchor';
    readonly basis:        string;
    readonly description:  string;
    readonly expected:     'refused';
    readonly document?:    DocumentRef & { patch: PatchOperation[] };
    readonly checkpoint?:  DocumentRef;
    readonly trustAnchor?: string;
    readonly at?:          string;
    readonly evseId?:      string;
    readonly keysFrom?:    DocumentRef;
    readonly text?:        string;
}

export const refusals = load<{ run: string, vectors: RefusalVector[] }>('poi-refusals.json');


// ---- Documents of the frozen run ----------------------------------------------------------------------------------

const RUN = new URL(`${history.run}/`, VECTORS);

const texts = new Map<string, string>();

/** A file of the run as text, read once. */
export function runText(file: string): string {
    let text = texts.get(file);
    if (text === undefined) {
        text = readFileSync(new URL(file, RUN), 'utf8');
        texts.set(file, text);
    }
    return text;
}

/** A document of the run, read as POI reads JSON (decimals as decimals, strings as strings); a copy of its own. */
export function runDocument(ref: DocumentRef | string): JSONValue {
    const { file, pointer } = typeof ref === 'string' ? { file: ref, pointer: '' } : ref;
    return clone(resolve(parseJSON(runText(file)), pointer, file));
}

function tokens(pointer: string): string[] {
    if (pointer === '')
        return [];
    if (!pointer.startsWith('/'))
        throw new Error(`No JSON pointer: '${pointer}'`);
    return pointer.slice(1).split('/').map(token => token.replaceAll('~1', '/').replaceAll('~0', '~'));
}

function resolve(document: JSONValue, pointer: string, where: string): JSONValue {
    let value = document;
    for (const token of tokens(pointer)) {
        const next = isArray(value) ? value[Number(token)] : isObject(value) ? value[token] : undefined;
        if (next === undefined)
            throw new Error(`${where}: the pointer '${pointer}' names nothing`);
        value = next;
    }
    return value;
}

/**
 * A document with a JSON patch applied (RFC 6902: add, replace, remove). The values of a patch are read as POI reads
 * JSON, so that a decimal stays a decimal.
 */
export function patched(ref: DocumentRef & { patch: readonly PatchOperation[] }): JSONValue {

    const document = runDocument(ref);

    for (const operation of ref.patch) {

        const path    = tokens(operation.path);
        const last    = path.pop();

        if (last === undefined)
            throw new Error('A patch of the whole document is not needed by any vector');

        const parent  = resolve(document, path.length === 0 ? '' : '/' + path.map(token => token.replaceAll('~', '~0').replaceAll('/', '~1')).join('/'), ref.file);
        const value   = operation.value === undefined ? undefined : parseJSON(JSON.stringify(operation.value));

        if (isArray(parent)) {
            const index = last === '-' ? parent.length : Number(last);
            if      (operation.op === 'remove')   parent.splice(index, 1);
            else if (operation.op === 'add')      parent.splice(index, 0, value as JSONValue);
            else                                  parent[index] = value as JSONValue;
        }
        else if (isObject(parent)) {
            if (operation.op === 'remove') delete parent[last];
            else                           parent[last] = value as JSONValue;
        }
        else
            throw new Error(`${ref.file}: the patch path '${operation.path}' names no container`);

    }

    return document;

}
