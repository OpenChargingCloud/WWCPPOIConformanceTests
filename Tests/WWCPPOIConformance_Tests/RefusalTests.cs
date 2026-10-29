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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// poi-refusals.json: documents an implementation must refuse - a document of the run with a JSON patch applied,
    /// checked at another time, against another trust anchor or checkpoint; or a text.
    /// </summary>
    [TestFixture]
    public class RefusalTests
    {

        public static IEnumerable<TestCaseData> Vectors()  => VectorFiles.Cases(VectorFiles.Refusals, "vectors");


        [Test]
        public void VectorsAreLoaded()

            => Assert.That(Vectors().Count(), Is.GreaterThanOrEqualTo(30));


        /// <summary>
        /// A history started from the snapshot a vector names, which must start one: it is no document under test.
        /// </summary>
        private static RoamingNetworkHistory HistoryFrom(JObject Snapshot)

            => RoamingNetworkHistory.TryFromSnapshot((JObject) VectorFiles.RunDocument(Snapshot), out var history, out var error)
                   ? history
                   : throw new InvalidOperationException($"The snapshot does not start a history: {error}");


        /// <summary>
        /// What a vector of its kind checks of the given document: whether it is taken, and why not. Of the control, every
        /// document as published, also the price statements a checkpoint names.
        /// </summary>
        private static Boolean Taken(JObject Vector, JToken? Document, out String? Error, Boolean Control = false)
        {

            JObject Need(String Name) => (JObject) (Vector[Name] ?? throw new InvalidOperationException($"The vector {Vector["id"]} names no {Name}!"));
            String  Text(String Name) => Vector[Name]?.Value<String>() ?? throw new InvalidOperationException($"The vector {Vector["id"]} names no {Name}!");

            switch (Vector["kind"]!.Value<String>())
            {

                case "commit":
                    return RoamingNetworkCommit.TryParse((JObject) Document!, out _, out Error);

                case "checkpoint":
                    return RoamingNetworkCheckpoint.TryParse((JObject) Document!, out _, out Error);

                case "version":
                    return RoamingNetwork.TryParse((JObject) Document!, out _, out Error);

                case "checkpointProof":
                    return RoamingNetworkCheckpointProof.TryParse((JObject) Document!, out var checkpointProof, out Error) &&
                           checkpointProof.Verify(HistoryTests.Checkpoint(Need("checkpoint")), out Error);

                case "stationProof":
                    return RoamingNetworkProof.TryParse((JObject) Document!, out var proof, out Error) &&
                           proof.Verify(HistoryTests.TrustAnchor(Text("trustAnchor")), out _, out Error, HistoryTests.Time(Text("at")));

                case "priceStatement":
                    if (!RoamingNetworkPriceStatement.TryParse((JObject) Document!, out var statement, out Error))
                        return false;
                    var network   = (JObject) VectorFiles.RunDocument(Need("keysFrom"));
                    var operator_ = ((JArray) network["chargingStationOperators"]!).Cast<JObject>().Single(cso => cso["@id"]!.Value<String>() == statement.Signer.ToString());
                    var keys      = ((JArray) operator_["signingKeys"]!).Cast<JObject>().Select(json => POIPublicKey.TryParse(json, out var key, out var keyError) ? key : throw new InvalidOperationException(keyError)).ToArray();
                    return statement.TryVerify(keys, out Error);

                // A price statement against the roaming network as it names its entity: taken by a history started from
                // the snapshot of the version it was made against, at the time of the vector, as a server takes one.
                case "entityPriceStatement":
                    if (!RoamingNetworkPriceStatement.TryParse((JObject) Document!, out var ofEntity, out Error))
                        return false;
                    var result = HistoryFrom(Need("snapshot")).TryAddPriceStatement(ofEntity, out Error, HistoryTests.Time(Text("at")));
                    Error ??= result == POIPriceStatementResult.Taken ? null : $"The price statement is {result}, not taken!";
                    return result == POIPriceStatementResult.Taken;

                // The price statements a checkpoint names: taken along with it by a history started from the snapshot of
                // its commit, which takes it as its first checkpoint, its signatures unchecked as in a replay.
                case "checkpointPriceStatements":
                    if (!RoamingNetworkCheckpoint.TryParse((JObject) Document!, out var named, out Error))
                        return false;
                    var statements = new List<RoamingNetworkPriceStatement>();
                    foreach (var json in (JArray) (Control ? VectorFiles.RunDocument(Need("priceStatements")) : VectorFiles.Patched(Need("priceStatements"))))
                    {
                        if (!RoamingNetworkPriceStatement.TryParse((JObject) json, out var priceStatement, out Error))
                            return false;
                        statements.Add(priceStatement);
                    }
                    return HistoryFrom(Need("snapshot")).TryAddCheckpoint(named, out Error, VerifyCheckpointSignature: (_, _) => true, PriceStatements: statements);

                case "trustAnchor":
                    return RoamingNetworkTrustAnchor.TryParse(Text("text"), out _, out Error);

                default:
                    throw new InvalidOperationException($"The kind '{Vector["kind"]}' is not known to this harness: the vector files are newer than the harness!");

            }

        }


        [TestCaseSource(nameof(Vectors))]
        public void Refuses(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            var reference = Vector["document"] as JObject;
            var document  = reference is null ? null : VectorFiles.Patched(reference);
            String? error;

            // The control: the document as published passes the same check, so the refusal is the patch's doing.
            if (reference is not null && ((JArray) reference["patch"]!).Count > 0)
                Assert.That(Taken(Vector, VectorFiles.RunDocument(reference), out error, Control: true), Is.True, () => $"The document as published is refused already: {error}");

            if (VectorFiles.Deviates(Vector))
            {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                Assert.That(Taken(Vector, document, out error), Is.True,
                            () => $"The known deviation is gone ({error}): remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
                return;
            }

            Assert.That(Taken(Vector, document, out error), Is.False, $"{Vector["description"]} - taken, but must be refused ({Vector["basis"]})");

            // Refused for what the vector is about, where it names it.
            if (Vector["reason"]?.Value<String>() is String reason)
                Assert.That(error, Does.Contain(reason), $"{Vector["id"]}: refused, but not for what it is about");

            TestContext.Out.WriteLine($"Refused: {error}");

        }

    }

}
