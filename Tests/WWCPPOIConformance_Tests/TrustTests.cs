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
    /// poi-trust.json: station proofs of the example network of SPECIFICATION.md section 6, signed with its keys, checked
    /// against a trust anchor at a point in time: what a verifier must take and refuse (8.4 to 8.6).
    /// </summary>
    [TestFixture]
    public class TrustTests
    {

        public static IEnumerable<TestCaseData> StationProofs()  => VectorFiles.Cases(VectorFiles.Trust, "stationProofs");


        [Test]
        public void VectorsAreLoaded()

            => Assert.That(StationProofs().Count(), Is.GreaterThanOrEqualTo(15));


        [TestCaseSource(nameof(StationProofs))]
        public void A_station_proof_against_a_trust_anchor(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            var text = (String Name) => Vector[Name]!.Value<String>()!;

            var proofJSON = (JObject) POIJSONReader.Read(text("proof"));

            // The root the proof leads to, whatever its attestations: also a proof refused for one of them, e.g. one without
            // a validUntil, leads to it.
            var unattested = (JObject) proofJSON.DeepClone();
            unattested.Remove(RoamingNetworkProof.PropertyKeys.Attestations);

            Assert.That(RoamingNetworkTrustAnchor.TryParse((JObject) POIJSONReader.Read(text("trustAnchor")), out var anchor, out var error), Is.True, error);
            Assert.That(RoamingNetworkProof.TryParse(unattested, out var network, out error),                                            Is.True, error);
            Assert.That(network!.TryCalculateETag(out var root, out error),                                                              Is.True, error);
            Assert.That(root.ToString(),                                                                                                  Is.EqualTo(text("root")));

            // A proof whose attestations can not be read is refused, as one they do not attest.
            var taken    = RoamingNetworkProof.TryParse(proofJSON, out var proof, out error) &&
                           proof.Verify(anchor!, out _, out error, HistoryTests.Time(text("at")));
            var accepted = text("expected") == "accepted";

            // A known deviation is pinned: the day it is gone, this turns red and the marker is removed in the generator.
            if (VectorFiles.Deviates(Vector))
                Assert.That(taken, Is.EqualTo(!accepted), () => $"The known deviation is gone ({error ?? "taken"}): remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
            else
                Assert.That(taken, Is.EqualTo(accepted),  () => $"{text("description")} ({text("basis")}): {(taken ? "taken" : error)}");

            TestContext.Out.WriteLine(taken ? "Taken." : $"Refused: {error}");

        }

    }

}
