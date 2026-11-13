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

#region Usings

using System.Globalization;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// poi-evtaler.json: the amounts of EV Taler (concepts/EVTaler.md of WWCP_POI, open point 3) - the gross rates of the
    /// simple profile of a charging tariff, what a step costs, rounded up to the minor unit of its currency, and the price
    /// of a session, rounded to the nearest minor unit, half away from zero.
    /// </summary>
    [TestFixture]
    public class EVTalerTests
    {

        public static IEnumerable<TestCaseData> Vectors()  => VectorFiles.Cases(VectorFiles.EVTaler, "vectors");


        [Test]
        public void VectorsAreLoaded()
        {
            Assert.That(Vectors().Count(), Is.GreaterThanOrEqualTo(1));
        }


        /// <summary>
        /// The rates of the charging tariff of a vector, priced by its own elements, or why it has none.
        /// </summary>
        private static EVTalerRates? RatesOf(JObject Vector, out String? Reason)
        {

            // Read as POI reads JSON: the tariff is given as text, for the text of its numbers matters.
            var tariff    = (JObject) POIJSON.Read(Vector["tariff"]!.Value<String>()!);
            var elements  = tariff["elements"] is JArray array
                                ? array.Cast<JObject>().ToArray()
                                : [];

            return EVTalerRates.TryOf(Vector["currency"]!.Value<String>()!, tariff, elements, out var rates, out Reason)
                       ? rates
                       : null;

        }

        private static EVTalerRates PricedBy(JObject Vector)
            => RatesOf(Vector, out var reason)
                   ?? throw new InvalidOperationException($"The charging tariff of the vector has no rates: {reason}");

        private static String? Written(Decimal? Value)
            => Value.HasValue
                   ? EVTalerAmounts.WriteDecimal(Value.Value)
                   : null;


        [Test, TestCaseSource(nameof(Vectors))]
        public void Amount(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            var currency  = Vector["currency"]!.Value<String>()!;
            var expected  = Vector["expected"]!.Value<String>()!;
            var deviates  = VectorFiles.Deviates(Vector);

            if (expected is not "priced" and not "notPriced")
                Assert.Fail($"A vector expecting '{expected}' is not known to this harness: the vector files are newer than the harness!");

            switch (Vector["check"]!.Value<String>())
            {

                case "rates": {

                    var rates = RatesOf(Vector, out var reason);

                    if (expected == "notPriced")
                    {
                        if (deviates) { Assert.That(rates, Is.Not.Null, "Pinned: the known deviation no longer holds - remove the marker in the generator"); return; }
                        Assert.That(rates,  Is.Null, "The charging tariff has rates");
                        Assert.That(reason, Is.EqualTo(Vector["reason"]!.Value<String>()));
                        return;
                    }

                    Assert.That(rates, Is.Not.Null, reason);

                    var given = new JObject();

                    void Add(String Name, Decimal? Value)
                    {
                        if (Written(Value) is String text)
                            given.Add(Name, text);
                    }

                    Add("energyPerKWh",     rates!.EnergyPerKWh);
                    Add("energyStepWh",     rates. EnergyStepWh);
                    Add("timePerHour",      rates. TimePerHour);
                    Add("timeStepSeconds",  rates. TimeStepSeconds);
                    Add("flatFee",          rates. FlatFee);

                    Assert.That(rates.Currency, Is.EqualTo(currency));

                    if (deviates) { Assert.That(JToken.DeepEquals(given, Vector["rates"]), Is.False, "Pinned: the known deviation no longer holds - remove the marker in the generator"); return; }

                    Assert.That(JToken.DeepEquals(given, Vector["rates"]), Is.True, $"The rates are {given.ToString(Newtonsoft.Json.Formatting.None)}");
                    return;

                }

                case "step": {

                    if (!EVTalerCovers.TryParse(Vector["covers"], out var covers, out var coversError))
                        throw new InvalidOperationException($"What the step of the vector covers does not read: {coversError}");

                    var priced = PricedBy(Vector).TryGetStepPrice(covers, out var price, out var error);

                    if (expected == "notPriced")
                    {
                        if (deviates) { Assert.That(priced, Is.True, "Pinned: the known deviation no longer holds - remove the marker in the generator"); return; }
                        Assert.That(priced, Is.False, $"The step costs {EVTalerAmounts.Write(price, currency)}");
                        Assert.That(error,  Is.EqualTo(Vector["reason"]!.Value<String>()));
                        return;
                    }

                    Assert.That(priced, Is.True, error);

                    if (deviates) { Assert.That(EVTalerAmounts.Write(price, currency), Is.Not.EqualTo(Vector["price"]!.Value<String>()), "Pinned: the known deviation no longer holds - remove the marker in the generator"); return; }

                    Assert.That(EVTalerAmounts.Write(price, currency), Is.EqualTo(Vector["price"]!.Value<String>()));
                    return;

                }

                case "session": {

                    var energy    = Decimal.Parse(Vector["energy"]!.Value<String>()!, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
                    var duration  = TimeSpan.FromTicks(Vector["durationMs"]!.Value<Int64>() * TimeSpan.TicksPerMillisecond);
                    var price     = EVTalerAmounts.Write(PricedBy(Vector).SessionPrice(energy, duration), currency);

                    if (expected != "priced")
                        Assert.Fail("The price of a session is calculated: the vector files are newer than the harness!");

                    if (deviates) { Assert.That(price, Is.Not.EqualTo(Vector["price"]!.Value<String>()), "Pinned: the known deviation no longer holds - remove the marker in the generator"); return; }

                    Assert.That(price, Is.EqualTo(Vector["price"]!.Value<String>()));
                    return;

                }

                default:
                    Assert.Fail($"A check '{Vector["check"]}' is not known to this harness: the vector files are newer than the harness!");
                    return;

            }

        }

    }

}
