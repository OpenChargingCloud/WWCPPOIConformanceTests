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
    /// poi-histories.json: small histories the generator made and signed with keys whose seeds it gives, replayed step by
    /// step: what a history takes, and what it refuses - each refusal with its control, the document refused but for what
    /// the replay is about, taken in its place.
    /// </summary>
    [TestFixture]
    public class HistoriesTests
    {

        public static IEnumerable<TestCaseData> Replays()            => VectorFiles.Cases(VectorFiles.Histories, "replays");
        public static IEnumerable<TestCaseData> AnchoredSnapshots()  => VectorFiles.Cases(VectorFiles.Histories, "anchoredSnapshots");


        [Test]
        public void VectorsAreLoaded()
        {
            Assert.That(Replays().Count(),            Is.GreaterThanOrEqualTo(1));
            Assert.That(AnchoredSnapshots().Count(),  Is.GreaterThanOrEqualTo(1));
        }


        /// <summary>
        /// Take the given steps one after the other, the last one with the given document, if any: the history after the
        /// last one taken, and whether every step was taken.
        /// </summary>
        private static Boolean TrySteps(JObject Vector, IEnumerable<JObject> Steps, out RoamingNetworkHistory? History, out String? Error)
        {

            var history    = (JObject) ((JArray) VectorFiles.Histories["histories"]!).Single(item => item["id"]!.Value<String>() == Vector["history"]!.Value<String>());
            var documents  = (JObject) history["documents"]!;

            History = null;
            Error   = null;

            foreach (var step in Steps)
                if (!Replay.TryStep(ref History, step, step => POIJSON.Read(documents[step["document"]!.Value<String>()!]!.Value<String>()!), out Error))
                {
                    Error = $"{step["op"]} {step["document"]}: {Error}";
                    return false;
                }

            return true;

        }


        [TestCaseSource(nameof(Replays))]
        public void A_history_takes_and_refuses(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            // The replay checks the content; who may sign commits and checkpoints is the verifier's business, not its.
            Assert.That(Vector["commitAndCheckpointSignatures"]?.Value<String>(), Is.EqualTo("unchecked"), "A replay of another kind is not known to this harness");

            var steps = ((JArray) Vector["steps"]!).Cast<JObject>().ToArray();
            String? error;

            if (Vector["expected"]!.Value<String>() == "accepted")
            {
                Assert.That(TrySteps(Vector, steps, out _, out error), Is.True, error);
                return;
            }

            var last     = steps[^1];
            var control  = (JObject) last.DeepClone();
            control["document"] = Vector["control"] ?? throw new InvalidOperationException($"The refusal {Vector["id"]} names no control!");

            // The control: in place of the refused document, the one refused but for what the replay is about is taken.
            Assert.That(TrySteps(Vector, [ .. steps[..^1], control ], out _, out error), Is.True, () => $"The control is refused: {error}");

            Assert.That(TrySteps(Vector, steps[..^1], out _, out error), Is.True, error);
            var taken = TrySteps(Vector, steps, out _, out error);

            if (VectorFiles.Deviates(Vector))
            {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                Assert.That(taken, Is.True, () => $"The known deviation is gone ({error}): remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
                return;
            }

            Assert.That(taken, Is.False, $"{Vector["description"]} - taken, but must be refused ({Vector["basis"]})");

            // Refused for what the vector is about, where it names it.
            if (Vector["reason"]?.Value<String>() is String reason)
                Assert.That(error, Does.Contain(reason), $"{Vector["id"]}: refused, but not for what it is about");

            TestContext.Out.WriteLine($"Refused: {error}");

        }


        /// <summary>
        /// Start a history from the snapshot of the head or of a checkpoint the given case names, as RoamingNetworkPeer
        /// starts from another server (SPECIFICATION.md, section 10.5, Anchored): only anchored in the trust anchor it names,
        /// at the time it names.
        /// </summary>
        private static Boolean TryStartAnchored(JObject Vector, JObject Case, out String? Error)
        {

            var history   = (JObject) ((JArray) VectorFiles.Histories["histories"]!).Single(item => item["id"]!.Value<String>() == Vector["history"]!.Value<String>());
            var snapshot  = (JObject) POIJSON.Read(history["documents"]![Case["document"]!.Value<String>()!]!.Value<String>()!);
            var at        = HistoryTests.Time(Case["at"]!.Value<String>()!);

            if (!RoamingNetworkTrustAnchor.TryParse((JObject) POIJSON.Read(Case["trustAnchor"]!.Value<String>()!), out var trustAnchor, out Error))
                return false;

            return Vector["snapshot"]!.Value<String>() switch {

                       // Its head attested by the attestations it carries, as the roaming network operator attested it.
                       "head"        => RoamingNetworkHistory.TryFromAnchoredSnapshot          (snapshot, trustAnchor, out _, out Error, At: at),

                       // Its checkpoint signed by the roaming network operator as the trust anchor requires.
                       "checkpoint"  => RoamingNetworkHistory.TryFromAnchoredCheckpointSnapshot(snapshot, trustAnchor, out _, out Error, VerifyCheckpointSignature: (_, _) => true, At: at),

                       _             => throw new InvalidOperationException($"A snapshot of a '{Vector["snapshot"]}' is not known to this harness: the vector files are newer than the harness!")

                   };

        }


        [TestCaseSource(nameof(AnchoredSnapshots))]
        public void A_snapshot_anchored_in_the_trust_anchor(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            // What anchors the history is checked against the trust anchor; the other signatures are the verifier's business.
            Assert.That(Vector["commitAndCheckpointSignatures"]?.Value<String>(), Is.EqualTo("unchecked"), "A snapshot of another kind is not known to this harness");

            String? error;

            if (Vector["expected"]!.Value<String>() == "accepted")
            {
                Assert.That(TryStartAnchored(Vector, Vector, out error), Is.True, error);
                return;
            }

            // The control: the snapshot, the trust anchor and the time, what the vector is about given otherwise, taken.
            var control = (JObject) (Vector["control"] ?? throw new InvalidOperationException($"The refusal {Vector["id"]} names no control!"));
            Assert.That(TryStartAnchored(Vector, control, out error), Is.True, () => $"The control is refused: {error}");

            var taken = TryStartAnchored(Vector, Vector, out error);

            if (VectorFiles.Deviates(Vector))
            {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                Assert.That(taken, Is.True, () => $"The known deviation is gone ({error}): remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
                return;
            }

            Assert.That(taken, Is.False, $"{Vector["description"]} - taken, but must be refused ({Vector["basis"]})");

            // Refused for what the vector is about, where it names it.
            if (Vector["reason"]?.Value<String>() is String reason)
                Assert.That(error, Does.Contain(reason), $"{Vector["id"]}: refused, but not for what it is about");

            TestContext.Out.WriteLine($"Refused: {error}");

        }

    }

}
