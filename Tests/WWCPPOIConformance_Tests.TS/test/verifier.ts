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

import { HistoricalTrustContext, initialTrustEpoch, isArray, isObject, KeyStatement, parseJSON, parseTrustedWitnesses, parseWitnessPublicationPolicy,
         pricePublicationOfferHashes, PriceStatement, TrustAnchor, TrustContext, TrustTransition, trustPolicyId, trustStatementDigest,
         verifyChargingDocumentKeys, verifyHistoricalMeterEvidence, verifyMeterKey, verifySessionPriceEvidence, VerifiedTrustTransition,
         type JSONObject, type JSONValue } from '../../../libs/WWCP_POI.TS/src/index.ts';

import type { Applicability } from './vectors.ts';


// ---- poi-verifier.json: the verifier extensions of WWCP_POI.TS 0.2.0, of the fixtures of ChargyWebApp ---------------

/**
 * A document of the fixtures: a file of the run and a JSON pointer (RFC 6901) into it, "" for the whole file. Where the
 * pointer goes on into a string, the string is a JSON document of its own (a fixture keeps signed decimals so).
 */
export interface ChargyRef { readonly file: string, readonly pointer: string }

/** The local trust a verification starts from: every identity key of the trust anchor, at a time. */
export interface TrustCase {
    /** The QR code of the trust anchor. */
    readonly anchor:        ChargyRef;
    /** The key statement of the roaming network operator. */
    readonly keyStatement:  ChargyRef;
    readonly at:            string;
    /** A context of now, or a historical one of a key statement saved before (HistoricalTrustContext). */
    readonly context:       'current' | 'historical';
}

export interface VerifierRequest {
    readonly evseId?:               string;
    readonly meterSerialNumber?:    string;
    readonly meterId?:              string;
    readonly keyId?:                string;
    readonly keyFormat?:            'spki-der' | 'cose-key';
    readonly measurementTimes?:     readonly string[];
    readonly chargingStarted?:      string;
    readonly startDocumentSHA256?:  string;
    readonly operatorId?:           string;
    readonly at?:                   string;
}

export interface VerifierPolicy {
    readonly witnesses?:          ChargyRef;
    readonly requiredWitnesses?:  number;
    readonly requirePublication?: boolean;
    readonly publicationPolicy?:  ChargyRef;
}

export interface VerifierCase {
    readonly trust?:           TrustCase;
    readonly proof?:           ChargyRef;
    readonly evidence?:        ChargyRef;
    readonly request?:         VerifierRequest;
    readonly policy?:          VerifierPolicy;
    readonly operator?:        ChargyRef;
    readonly transition?:      ChargyRef;
    readonly acceptedAt?:      string;
    readonly sequence?:        number;
    readonly trustAnchor?:     ChargyRef;
    readonly keyStatement?:    ChargyRef;
    readonly priceStatement?:  ChargyRef;
    readonly tariff?:          ChargyRef;
}

export interface VerifierVector extends Applicability, VerifierCase {
    readonly id:           string;
    readonly kind:         'meterKey' | 'historicalMeterEvidence' | 'sessionPrice' | 'trustTransition' | 'chargingDocumentKeys' | 'trustPolicyId' | 'keyStatementDigest' | 'offerHashes';
    readonly basis:        string;
    readonly description:  string;
    readonly expected:     'accepted' | 'refused';
    /** Of an accepted vector: what both implementations give, normalized (see results()). */
    readonly result?:      JSONObject;
    /** Of a refusal: the same check, of what the vector is about given otherwise, taken. */
    readonly control?:     VerifierCase;
    /** What the refusal names, as both implementations word it. */
    readonly reason?:      string;
}


export const verifier = JSON.parse(readFileSync(new URL('../../../test-vectors/poi-verifier.json', import.meta.url), 'utf8')) as { run: string, vectors: VerifierVector[] };

const RUN = new URL(`../../../test-vectors/${verifier.run}/`, import.meta.url);

const texts = new Map<string, string>();

/** A document of the fixtures, read as POI reads JSON; a pointer into a string reads the string as JSON. */
export function chargyDocument(ref: ChargyRef): JSONValue {

    let text = texts.get(ref.file);
    if (text === undefined) {
        text = readFileSync(new URL(ref.file, RUN), 'utf8');
        texts.set(ref.file, text);
    }

    let value: JSONValue = parseJSON(text);
    for (const token of ref.pointer === '' ? [] : ref.pointer.slice(1).split('/').map(item => item.replaceAll('~1', '/').replaceAll('~0', '~'))) {
        if (typeof value === 'string')
            value = parseJSON(value);
        const next: JSONValue | undefined = isArray(value) ? value[Number(token)] : isObject(value) ? value[token] : undefined;
        if (next === undefined)
            throw new Error(`${ref.file}: the pointer '${ref.pointer}' names nothing`);
        value = next;
    }
    return typeof value === 'string' && value.startsWith('{') ? parseJSON(value) : value;

}

const text  = (ref: ChargyRef): string     => { const value = chargyDocument(ref); if (typeof value !== 'string') throw new Error(`${ref.file}#${ref.pointer} is no text`); return value; };
const time  = (iso: string | undefined): number => { if (iso === undefined) throw new Error('The vector names no time'); return Date.parse(iso); };
const given = <T>(value: T | undefined, what: string): T => { if (value === undefined) throw new Error(`The vector names no ${what}`); return value; };

/** The local trust of a case: every identity key of its trust anchor trusted. */
function trustOf(trust: TrustCase | undefined): TrustContext | HistoricalTrustContext {
    const { anchor, keyStatement, at, context } = given(trust, 'trust');
    const trustAnchor  = TrustAnchor.parse(text(anchor));
    const statement    = KeyStatement.parse(chargyDocument(keyStatement));
    return context === 'historical'
               ? HistoricalTrustContext.create(trustAnchor, statement, { trustedIdentityKeyIds: trustAnchor.keys, now: time(at) })
               : TrustContext.create(trustAnchor, statement, { trustedIdentityKeyIds: trustAnchor.keys, at: time(at) });
}

const policyOf = (policy: VerifierPolicy | undefined) => ({
    ...(policy?.witnesses          === undefined ? {} : { witnesses: parseTrustedWitnesses(chargyDocument(policy.witnesses)) }),
    ...(policy?.requiredWitnesses  === undefined ? {} : { requiredWitnesses: policy.requiredWitnesses }),
    ...(policy?.requirePublication === undefined ? {} : { requirePublication: policy.requirePublication }),
    ...(policy?.publicationPolicy  === undefined ? {} : { publicationPolicy: parseWitnessPublicationPolicy(chargyDocument(policy.publicationPolicy)) }),
});

/**
 * Check a case as the vector says, with the API of WWCP_POI.TS, and give what both implementations give of it,
 * normalized: identifications, the words of the verdicts, counts, times in ISO 8601. A refusal throws.
 */
export function results(kind: VerifierVector['kind'], check: VerifierCase): JSONObject {

    const request = check.request ?? {};

    switch (kind) {

        case 'meterKey': {
            const current = trustOf(check.trust);
            if (!(current instanceof TrustContext))
                throw new Error('A meter key is bound with a current trust context');
            const binding = verifyMeterKey(current, chargyDocument(given(check.proof, 'proof')), {
                                evseId: given(request.evseId, 'EVSE'), meterSerialNumber: given(request.meterSerialNumber, 'serial number'), keyFormat: given(request.keyFormat, 'key format'),
                                ...(request.meterId === undefined ? {} : { meterId: request.meterId }), ...(request.keyId === undefined ? {} : { keyId: request.keyId }) });
            return { evseId: binding.evseId, chargingStationId: binding.chargingStationId, meterId: binding.meterId, meterSerialNumber: binding.meterSerialNumber,
                     keyId: binding.key.id, keyIdScheme: binding.key.idScheme, canonicalKeyId: binding.key.canonicalId, association: binding.evidence.association };
        }

        case 'historicalMeterEvidence': {
            const result = verifyHistoricalMeterEvidence(trustOf(check.trust), chargyDocument(given(check.evidence, 'evidence')), {
                               evseId: given(request.evseId, 'EVSE'), meterSerialNumber: given(request.meterSerialNumber, 'serial number'),
                               measurementTimes: given(request.measurementTimes, 'measurement times').map(item => time(item)), keyFormat: given(request.keyFormat, 'key format') },
                               policyOf(check.policy));
            return { bindings:      result.bindings.map(binding => ({ meterId: binding.meterId, keyId: binding.key.id, association: binding.evidence.association })),
                     publications:  result.versions.map(version => version.publication),
                     independentTime: result.independentTime };
        }

        case 'sessionPrice': {
            const result = verifySessionPriceEvidence(trustOf(check.trust), chargyDocument(given(check.evidence, 'evidence')), {
                               evseId: given(request.evseId, 'EVSE'), meterSerialNumber: given(request.meterSerialNumber, 'serial number'),
                               chargingStarted: time(request.chargingStarted), startDocumentSHA256: given(request.startDocumentSHA256, 'start document') },
                               policyOf(check.policy));
            return { signatures: result.signatures, agreement: result.agreement, applicability: result.applicability, publication: result.publication,
                     publicationBeforeStart: result.publicationBeforeStart, customerConsent: result.customerConsent, witnessedBy: [ ...result.witnessedBy ],
                     selected: result.selected === undefined ? null : { digest: result.selected.digest, algorithm: String(result.selected.statement['algorithm']),
                                                                         energyPerKWh: result.selected.rates?.energyPerKWh ?? null },
                     organizations: result.publicationWitnesses === undefined ? null : [ ...result.publicationWitnesses.organizations ] };
        }

        case 'trustTransition': {
            const basis = trustOf(check.trust);
            if (!(basis instanceof TrustContext))
                throw new Error('A trust transition continues a current trust context');
            const verified = VerifiedTrustTransition.verify(basis, chargyDocument(given(check.operator, 'operator')), TrustTransition.parse(chargyDocument(given(check.transition, 'transition'))),
                                                            { acceptedAt: time(check.acceptedAt), epoch: initialTrustEpoch(), sequence: given(check.sequence, 'sequence') });
            return { requiredConsensus: verified.context.requiredConsensus, signedByOld: verified.signedBy.old.length, signedByNext: verified.signedBy.next.length,
                     policyId: trustPolicyId(verified.context.anchor), epoch: verified.epoch.number };
        }

        case 'chargingDocumentKeys': {
            const keys = verifyChargingDocumentKeys(trustOf(check.trust), chargyDocument(given(check.proof, 'proof')),
                                                    { evseId: given(request.evseId, 'EVSE'), operatorId: given(request.operatorId, 'operator'), at: time(request.at) });
            return { chargingStationId: keys.chargingStationId, keys: keys.keys.map(key => ({ id: key.id, algorithm: key.algorithm })) };
        }

        case 'trustPolicyId':
            return { policyId: trustPolicyId(TrustAnchor.parse(text(given(check.trustAnchor, 'trust anchor')))) };

        case 'keyStatementDigest':
            return { digest: trustStatementDigest(KeyStatement.parse(chargyDocument(given(check.keyStatement, 'key statement')))) };

        case 'offerHashes': {
            const tariff = chargyDocument(given(check.tariff, 'tariff'));
            if (!isObject(tariff))
                throw new Error('The tariff is no object');
            const hashes = pricePublicationOfferHashes(PriceStatement.parse(chargyDocument(given(check.priceStatement, 'price statement'))), tariff);
            return { priceStatementSHA256: hashes.priceStatementSHA256, tariffSHA256: hashes.tariffSHA256 };
        }

        default:
            throw new Error(`A verifier vector of the kind '${String(kind)}' is not known to this harness: the vector files are newer than the harness!`);

    }

}
