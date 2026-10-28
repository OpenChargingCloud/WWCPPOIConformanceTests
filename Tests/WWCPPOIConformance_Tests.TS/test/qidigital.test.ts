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

import { DigitalCalibrationCertificate, DigitalCertificateOfConformity, DigitalDeclarationOfConformity, effectiveChargingStationOperator, isObject,
         QIDigitalItem, RoamingNetwork, type JSONObject, type JSONValue } from '../../../libs/WWCP_POI.TS/src/index.ts';

import { deviates, patched, qiDigital, qiDigitalDocument, skipReason, type QIDigitalCase, type QIDigitalVector } from './vectors.ts';


/** The roaming network of a case, which must read: it is no document under test. */
function networkOf(check: QIDigitalCase): RoamingNetwork {
    if (check.network === undefined)
        throw new Error('The case names no roaming network');
    return RoamingNetwork.parse(patched(check.network));
}

/** The certificate of conformity a declaration is checked against, which must read: it is no document under test. */
function certificateOf(check: QIDigitalCase): DigitalCertificateOfConformity {
    if (check.certificate === undefined)
        throw new Error('The case names no certificate of conformity');
    return DigitalCertificateOfConformity.parse(patched(check.certificate));
}

/** The energy meter of the EVSE a case names, as its roaming network names it at runtime, as a QI-Digital item. */
function meterOf(check: QIDigitalCase): QIDigitalItem {

    const operator  = networkOf(check).chargingStationOperator(check.chargingStationOperatorId ?? '');
    const objects   = (value: JSONValue | undefined): JSONObject[] => Array.isArray(value) ? value.filter(isObject) : [];
    const evse      = operator === undefined ? undefined
                    : objects(effectiveChargingStationOperator(operator)['chargingPools']).
                          flatMap(pool    => objects(pool['chargingStations'])).
                          flatMap(station => objects(station['EVSEs'])).
                          find(candidate  => candidate['@id'] === check.evseId);
    const meter     = evse?.['energyMeter'];

    if (!isObject(meter))
        throw new Error(`The roaming network of the case has no energy meter of the EVSE '${check.evseId ?? ''}'`);

    return QIDigitalItem.ofEnergyMeter(meter);

}

/**
 * Check the document of the given case as the vector says (SPECIFICATION.md does not hold the QI-Digital documents;
 * example A14 and WWCP_POI3/RoamingNetwork/QIDigital do): read, then verified against the roaming network at the time of
 * the case, checked against the certificate of the case, or covering the meter of the case. A refusal throws.
 */
function check(vector: QIDigitalVector, given: QIDigitalCase): void {

    const document = qiDigitalDocument(given.document);

    switch (vector.check) {

        case 'verify': {
            const network  = networkOf(given);
            const parse    = { certificateOfConformity:  (json: JSONValue) => DigitalCertificateOfConformity.parse(json),
                               declarationOfConformity:  (json: JSONValue) => DigitalDeclarationOfConformity.parse(json),
                               calibrationCertificate:   (json: JSONValue) => DigitalCalibrationCertificate.parse(json) }[vector.kind];
            if (parse === undefined)
                throw new Error(`A QI-Digital document of the kind '${String(vector.kind)}' is not known to this harness: the vector files are newer than the harness!`);
            parse(document).verify(network, given.at);
            return;
        }

        // The declaration against a certificate it names: no signature is looked at, the certificate's own check tells
        // whether it is valid.
        case 'certificate':
            DigitalDeclarationOfConformity.parse(document).verifyCertificate(certificateOf(given));
            return;

        case 'cover':
            DigitalCertificateOfConformity.parse(document).cover(meterOf(given));
            return;

        default:
            throw new Error(`The QI-Digital check '${String(vector.check)}' is not known to this harness: the vector files are newer than the harness!`);

    }

}


describe('poi-qidigital.json: the QI-Digital documents of example A14, checked as it checks them', () => {

    for (const vector of qiDigital.vectors) {

        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.expected}): ${vector.description}`, () => {

            if (vector.expected === 'accepted') {
                check(vector, vector);
                return;
            }

            if (vector.control === undefined)
                throw new Error(`The refusal ${vector.id} names no control`);

            // The control: the same check of the documents of the run, against QA as published, taken.
            check(vector, vector.control);

            if (deviates(vector)) {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                check(vector, vector);
                return;
            }

            // Refused for what the vector is about, where it names it.
            if (vector.reason === undefined)
                expect(() => { check(vector, vector); }).toThrow();
            else
                expect(() => { check(vector, vector); }).toThrow(vector.reason);

        });

    }

});
