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

import { EVTalerCovers, EVTalerRates, isArray, isObject, NetDecimal, parseJSON, writeAmount, writeDecimal } from '../../../libs/WWCP_POI.TS/src/index.ts';

import { deviates, evTaler, skipReason, type EVTalerRatesGiven, type EVTalerVector } from './vectors.ts';


/** The rates of the charging tariff of a vector, priced by its own elements, or why it has none. */
function ratesOf(vector: EVTalerVector): EVTalerRates | { readonly reason: string } {

    // Read as POI reads JSON: the tariff is given as text, for the text of its numbers matters.
    const tariff = parseJSON(vector.tariff);

    if (!isObject(tariff))
        throw new Error('The charging tariff of the vector is no JSON object');

    const elements = tariff['elements'];

    return EVTalerRates.of(vector.currency, tariff, isArray(elements) ? elements.filter(isObject) : []);

}

function pricedBy(vector: EVTalerVector): EVTalerRates {
    const rates = ratesOf(vector);
    if (!(rates instanceof EVTalerRates))
        throw new Error(`The charging tariff of the vector has no rates: ${rates.reason}`);
    return rates;
}

function decimalOf(text: string | undefined): NetDecimal {
    const value = text === undefined ? undefined : NetDecimal.parse(text);
    if (value === undefined)
        throw new Error(`The vector gives no decimal: '${text ?? ''}'`);
    return value;
}

/** The rates as a vector gives them: decimals as texts without trailing zeros, each where the tariff has it. */
function given(rates: EVTalerRates): EVTalerRatesGiven {
    const written = (value: NetDecimal | undefined) => value === undefined ? undefined : writeDecimal(value);
    return JSON.parse(JSON.stringify({ energyPerKWh:     written(rates.energyPerKWh),
                                       energyStepWh:     written(rates.energyStepWh),
                                       timePerHour:      written(rates.timePerHour),
                                       timeStepSeconds:  written(rates.timeStepSeconds),
                                       flatFee:          written(rates.flatFee) })) as EVTalerRatesGiven;
}


describe('poi-evtaler.json: the amounts of EV Taler, what a step and a session cost', () => {

    for (const vector of evTaler.vectors) {

        it.skipIf(skipReason(vector) !== undefined)(`${vector.id} (${vector.check}, ${vector.expected}): ${vector.description}`, () => {

            if (vector.expected !== 'priced' && vector.expected !== 'notPriced')
                throw new Error(`A vector expecting '${String(vector.expected)}' is not known to this harness: the vector files are newer than the harness!`);

            switch (vector.check) {

                case 'rates': {

                    const rates = ratesOf(vector);

                    if (vector.expected === 'notPriced') {
                        // Pinned: the known deviation still holds. Once it has none, remove the marker in the generator.
                        if (deviates(vector)) { expect(rates).toBeInstanceOf(EVTalerRates); return; }
                        expect(rates).toEqual({ reason: vector.reason });
                        return;
                    }

                    if (!(rates instanceof EVTalerRates))
                        throw new Error(`The charging tariff has no rates: ${rates.reason}`);

                    expect(rates.currency).toBe(vector.currency);

                    if (deviates(vector)) { expect(given(rates)).not.toEqual(vector.rates); return; }

                    expect(given(rates)).toEqual(vector.rates);
                    return;

                }

                case 'step': {

                    const price = pricedBy(vector).stepPrice(EVTalerCovers.parse(vector.covers));

                    if (vector.expected === 'notPriced') {
                        if (deviates(vector)) { expect(price).toBeInstanceOf(NetDecimal); return; }
                        expect(price).toBe(vector.reason);
                        return;
                    }

                    if (typeof price === 'string')
                        throw new Error(price);

                    if (deviates(vector)) { expect(writeAmount(price, vector.currency)).not.toBe(vector.price); return; }

                    expect(writeAmount(price, vector.currency)).toBe(vector.price);
                    return;

                }

                case 'session': {

                    if (vector.expected !== 'priced' || vector.durationMs === undefined)
                        throw new Error('The price of a session is calculated, of its duration: the vector files are newer than the harness!');

                    const price = writeAmount(pricedBy(vector).sessionPrice(decimalOf(vector.energy), vector.durationMs), vector.currency);

                    if (deviates(vector)) { expect(price).not.toBe(vector.price); return; }

                    expect(price).toBe(vector.price);
                    return;

                }

                default:
                    throw new Error(`A check '${String(vector.check)}' is not known to this harness: the vector files are newer than the harness!`);

            }

        });

    }

});
