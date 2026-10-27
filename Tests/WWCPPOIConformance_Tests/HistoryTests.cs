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

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// poi-history.json: what the C# examples A1 to A13 of WWCP_POI published in one run, frozen - checked by the
    /// implementation as it is now, so that the day it calculates otherwise than it did, this turns red.
    /// </summary>
    [TestFixture]
    public class HistoryTests
    {

        private static IEnumerable<TestCaseData> Of(String List)  => VectorFiles.Cases(VectorFiles.History, List);

        public static IEnumerable<TestCaseData> Versions()          => Of("versions");
        public static IEnumerable<TestCaseData> Commits()           => Of("commits");
        public static IEnumerable<TestCaseData> Checkpoints()       => Of("checkpoints");
        public static IEnumerable<TestCaseData> CheckpointProofs()  => Of("checkpointProofs");
        public static IEnumerable<TestCaseData> PriceStatements()   => Of("priceStatements");
        public static IEnumerable<TestCaseData> TrustAnchors()      => Of("trustAnchors");
        public static IEnumerable<TestCaseData> StationProofs()     => Of("stationProofs");
        public static IEnumerable<TestCaseData> Replays()           => Of("replays");


        private static String  Text  (JObject Vector, String Name) => Vector[Name]!.Value<String>()!;
        private static UInt64  Number(JObject Vector, String Name) => Vector[Name]!.Value<UInt64>();

        internal static DateTimeOffset Time(String Text)

            => DateTimeOffset.Parse(Text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);


        [Test]
        public void VectorsAreLoaded()
        {
            using (Assert.EnterMultipleScope())
            {
                Assert.That(Versions().Count(),       Is.GreaterThanOrEqualTo(10));
                Assert.That(Commits().Count(),        Is.GreaterThanOrEqualTo(40));
                Assert.That(StationProofs().Count(),  Is.GreaterThanOrEqualTo(4));
            }
        }


        [TestCaseSource(nameof(Versions))]
        public void A_version_and_its_ETags(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            Assert.That(RoamingNetwork.TryParse((JObject) VectorFiles.RunDocument(Vector), out var network, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(network!.Id.ToString(),                                Is.EqualTo(Text(Vector, "roamingNetworkId")));
                Assert.That(network.CalcETags().Select(eTag => eTag.ToString()),   Is.EqualTo(VectorFiles.Strings(Vector, "eTags")));
            }

        }

        [TestCaseSource(nameof(Commits))]
        public void A_commit_and_its_identification(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            Assert.That(RoamingNetworkCommit.TryParse((JObject) VectorFiles.RunDocument(Vector), out var commit, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(commit!.Id.ToString(),                         Is.EqualTo(Text(Vector, "commitId")));
                Assert.That(commit.RoamingNetworkId.ToString(),            Is.EqualTo(Text(Vector, "roamingNetworkId")));
                Assert.That(commit.Epoch,                                  Is.EqualTo(Number(Vector, "epoch")));
                Assert.That(commit.Revision,                               Is.EqualTo(Number(Vector, "revision")));
                Assert.That(commit.IdentificationHash.ToText(),            Is.EqualTo(Text(Vector, "hashAlgorithm")));
                Assert.That(commit.ETags.Select(eTag => eTag.ToString()),  Is.EqualTo(VectorFiles.Strings(Vector, "eTags")));
            }

        }

        [TestCaseSource(nameof(Checkpoints))]
        public void A_checkpoint_and_its_identification(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            Assert.That(RoamingNetworkCheckpoint.TryParse((JObject) VectorFiles.RunDocument(Vector), out var checkpoint, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(checkpoint!.Id.ToString(),                Is.EqualTo(Text(Vector, "checkpointId")));
                Assert.That(checkpoint.RoamingNetworkId.ToString(),   Is.EqualTo(Text(Vector, "roamingNetworkId")));
                Assert.That(checkpoint.Epoch,                         Is.EqualTo(Number(Vector, "epoch")));
                Assert.That(checkpoint.Sequence,                      Is.EqualTo(Number(Vector, "sequence")));
                Assert.That(checkpoint.Revision,                      Is.EqualTo(Number(Vector, "revision")));
                Assert.That(checkpoint.CommitId.ToString(),           Is.EqualTo(Text(Vector, "commitId")));
                Assert.That(checkpoint.IsFinal,                       Is.EqualTo(Vector["final"]!.Value<Boolean>()));
            }

        }

        internal static RoamingNetworkCheckpoint Checkpoint(JObject Reference)
        {
            Assert.That(RoamingNetworkCheckpoint.TryParse((JObject) VectorFiles.RunDocument(Reference), out var checkpoint, out var error), Is.True, error);
            return checkpoint!;
        }

        [TestCaseSource(nameof(CheckpointProofs))]
        public void A_commit_is_part_of_a_checkpoint(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            Assert.That(RoamingNetworkCheckpointProof.TryParse((JObject) VectorFiles.RunDocument(Vector), out var proof, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(proof!.CheckpointId.ToString(),                                  Is.EqualTo(Text(Vector, "checkpointId")));
                Assert.That(proof.CommitId.ToString(),                                       Is.EqualTo(Text(Vector, "commitId")));
                Assert.That(proof.Verify(Checkpoint((JObject) Vector["checkpoint"]!), out error), Is.True, error);
            }

        }

        [TestCaseSource(nameof(PriceStatements))]
        public void A_price_statement_and_its_digest(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            Assert.That(RoamingNetworkPriceStatement.TryParse((JObject) VectorFiles.RunDocument(Vector), out var statement, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(statement!.Sequence,  Is.EqualTo(Number(Vector, "sequence")));
                Assert.That(statement.Digest,     Is.EqualTo(Text(Vector, "digest")));
                Assert.That(statement.Previous,   Is.EqualTo(Vector["previous"]?.Value<String>()));
            }

        }

        internal static RoamingNetworkTrustAnchor CheckTrustAnchor(String QRCode, JObject Vector, String CanonicalJSONText)
        {

            Assert.That(RoamingNetworkTrustAnchor.TryParse(QRCode, out var anchor, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(anchor!.Id.ToString(),                                Is.EqualTo(Text(Vector, "roamingNetworkId")));
                Assert.That(anchor.URLs.Select(url => url.ToString()),           Is.EqualTo(VectorFiles.Strings(Vector, "urls")));
                Assert.That(anchor.Keys,                                          Is.EqualTo(VectorFiles.Strings(Vector, "keys")));
                Assert.That((UInt64) anchor.MinConsensus,                         Is.EqualTo(Number(Vector, "minConsensus")));
                Assert.That(CanonicalJSON.Serialize(anchor.ToJSON()),            Is.EqualTo(CanonicalJSONText));
                Assert.That(anchor.ToQRCode(),                                    Is.EqualTo(QRCode));
                Assert.That(RoamingNetworkTrustAnchor.TryParse((JObject) POIJSON.Read(CanonicalJSONText), out var fromJSON, out error), Is.True, error);
                Assert.That(fromJSON?.ToQRCode(),                                 Is.EqualTo(QRCode));
            }

            return anchor;

        }

        [TestCaseSource(nameof(TrustAnchors))]
        public void A_trust_anchor_and_its_QR_code(JObject Vector)
        {
            VectorFiles.SkipUnlessApplicable(Vector);
            CheckTrustAnchor(VectorFiles.RunText(Text(Vector, "file")).Trim(), Vector, Text(Vector, "json"));
        }

        internal static RoamingNetworkTrustAnchor TrustAnchor(String File)
        {
            Assert.That(RoamingNetworkTrustAnchor.TryParse(VectorFiles.RunText(File).Trim(), out var anchor, out var error), Is.True, error);
            return anchor!;
        }

        [TestCaseSource(nameof(StationProofs))]
        public void A_station_proof_verifies_against_the_trust_anchor(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            Assert.That(RoamingNetworkProof.TryParse((JObject) VectorFiles.RunDocument(Vector), out var proof, out var error), Is.True, error);
            Assert.That(proof!.TryCalculateETag(out var root, out error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(root.ToString(),                Is.EqualTo(Text(Vector, "root")));
                Assert.That(proof.CommitId?.ToString(),     Is.EqualTo(Text(Vector, "commitId")));
                Assert.That(proof.Revision,                 Is.EqualTo(Number(Vector, "revision")));
                Assert.That(proof.Verify(TrustAnchor(Text(Vector, "trustAnchor")), out _, out error, Time(Text(Vector, "at"))), Is.True, error);
            }

        }

        [TestCaseSource(nameof(Replays))]
        public void A_history_replayed_commit_by_commit(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            // The replay checks the content; who may sign commits and checkpoints is the verifier's business, not its.
            Assert.That(Vector["commitAndCheckpointSignatures"]?.Value<String>(), Is.EqualTo("unchecked"), "A replay of another kind is not known to this harness");

            RoamingNetworkHistory? history = null;

            foreach (var step in ((JArray) Vector["steps"]!).Cast<JObject>())
                Assert.That(Replay.TryStep(ref history, step, step => VectorFiles.RunDocument(Text(step, "file")), out var error), Is.True, $"{step["op"]}: {error}");

        }

    }

}
