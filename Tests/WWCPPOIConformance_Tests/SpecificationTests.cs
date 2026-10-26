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

using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// poi-specification.json: the examples of SPECIFICATION.md, section 6, every value as written there, and the content
    /// of the example with custom data (section 2).
    /// </summary>
    [TestFixture]
    public class SpecificationTests
    {

        private static IEnumerable<TestCaseData> Of(String List)  => VectorFiles.Cases(VectorFiles.Specification, List);

        public static IEnumerable<TestCaseData> Contents()           => Of("contents");
        public static IEnumerable<TestCaseData> Skeletons()          => Of("skeletons");
        public static IEnumerable<TestCaseData> Commits()            => Of("commits");
        public static IEnumerable<TestCaseData> Keys()               => Of("keys");
        public static IEnumerable<TestCaseData> Signatures()         => Of("signatures");
        public static IEnumerable<TestCaseData> InvalidSignatures()  => Of("invalidSignatures");
        public static IEnumerable<TestCaseData> PriceStatements()    => Of("priceStatements");
        public static IEnumerable<TestCaseData> TrustAnchors()       => Of("trustAnchors");


        internal static String Text(JObject Vector, String Name)

            => Vector[Name]!.Value<String>()!;

        internal static Byte[] Hash(String Algorithm, Byte[] Data)

            => Algorithm switch {
                   "sha256"  => SHA256.HashData(Data),
                   "sha384"  => SHA384.HashData(Data),
                   "sha512"  => SHA512.HashData(Data),
                   _         => throw new ArgumentException($"No hash algorithm of POI: {Algorithm}")
               };


        [TestCaseSource(nameof(Contents))]
        public void The_content_and_its_ETags(JObject Vector)
        {

            var content = (JObject) POIJSONReader.Read(Text(Vector, "content"));

            Assert.That(RoamingNetwork.TryParse(content, out var network, out var error), Is.True, error);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(CanonicalJSON.Serialize(content),                             Is.EqualTo(Text(Vector, "content")));
                // The content as the version holds it, read again: custom data as given (section 2).
                Assert.That(CanonicalJSON.Serialize(network!.ToJSON(IncludeETags: false)), Is.EqualTo(Text(Vector, "content")));
                Assert.That(network!.CalcETags().Select(eTag => eTag.ToString()),         Is.EqualTo(VectorFiles.Strings(Vector, "eTags")));
            }

        }

        [TestCaseSource(nameof(Skeletons))]
        public void A_skeleton_and_its_digest(JObject Vector)
        {

            var skeleton = POIJSONReader.Read(Text(Vector, "skeleton"));

            using (Assert.EnterMultipleScope())
            {
                Assert.That(CanonicalJSON.Serialize(skeleton),  Is.EqualTo(Text(Vector, "skeleton")));
                Assert.That(Convert.ToHexStringLower(Hash(Text(Vector, "hashAlgorithm"), [ 0x00, .. CanonicalJSON.ToUTF8Bytes(skeleton) ])),
                            Is.EqualTo(Text(Vector, "digest")));
            }

        }

        [TestCaseSource(nameof(Commits))]
        public void A_commit_and_its_identification(JObject Vector)
        {

            Assert.That(RoamingNetworkCommit.TryParse((JObject) Vector["commit"]!.DeepClone(), out var commit, out var error), Is.True, error);

            // What its identification is calculated over: its content with its JSON-LD context, without its @id.
            var content = commit!.ToJSON();
            content.Remove("@id");

            using (Assert.EnterMultipleScope())
            {
                Assert.That(commit.Id.ToString(),                       Is.EqualTo(Text(Vector, "commitId")));
                Assert.That(commit.IdentificationHash.ToText(),         Is.EqualTo(Text(Vector, "hashAlgorithm")));
                Assert.That(CanonicalJSON.Serialize(content),           Is.EqualTo(Text(Vector, "content")));
            }

        }

        [TestCaseSource(nameof(Keys))]
        public void A_key_and_its_thumbprint(JObject Vector)
        {

            var cose = Convert.FromBase64String(Text(Vector, "coseKey"));

            using (Assert.EnterMultipleScope())
            {
                Assert.That(new POIPublicKey(COSEKey.Parse(cose)).Id,                                                                     Is.EqualTo(Text(Vector, "keyId")));
                Assert.That(POIPublicKey.TryParse(new JObject(new JProperty("@id", Text(Vector, "keyId")), new JProperty("key", Text(Vector, "coseKey"))), out _, out var error), Is.True, error);
                Assert.That(POIPublicKey.TryParse(new JObject(new JProperty("@id", new String('0', 64)),   new JProperty("key", Text(Vector, "coseKey"))), out _, out _),         Is.False, "another @id than the thumbprint");
            }

        }

        private static Boolean Verifies(JObject Vector, out String? Error)
        {

            Error = null;

            if (!COSEAlgorithm.TryParse(Text(Vector, "algorithm"), out var algorithm))
            {
                Error = $"No COSE algorithm '{Text(Vector, "algorithm")}'";
                return false;
            }

            return algorithm.Verify(Encoding.UTF8.GetBytes(Text(Vector, "input")),
                                    Convert.FromBase64String(Text(Vector, "value")),
                                    COSEKey.Parse(Convert.FromBase64String(Text(Vector, "coseKey"))).ToPublicKey(),
                                    out Error);

        }

        [TestCaseSource(nameof(Signatures))]
        public void A_signature_verifies(JObject Vector)
        {

            using (Assert.EnterMultipleScope())
            {
                Assert.That(CanonicalJSON.Serialize(POIJSONReader.Read(Text(Vector, "input"))),  Is.EqualTo(Text(Vector, "input")));
                Assert.That(Verifies(Vector, out var error),                                       Is.True, error);
            }

        }

        [TestCaseSource(nameof(Signatures))]
        public void A_signature_is_made_again_from_its_private_seed(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(new JObject(new JProperty("requires", new JArray("signing"))));

            Assert.That(COSEAlgorithm.TryParse(Text(Vector, "algorithm"), out var algorithm), Is.True);

            var signature = algorithm.Sign(Encoding.UTF8.GetBytes(Text(Vector, "input")),
                                           new Ed25519PrivateKeyParameters(Convert.FromHexString(Text(Vector, "privateSeed")), 0),
                                           Deterministic: true);

            Assert.That(Convert.ToBase64String(signature), Is.EqualTo(Text(Vector, "value")));

        }

        [TestCaseSource(nameof(InvalidSignatures))]
        public void A_signature_does_not_verify(JObject Vector)

            => Assert.That(Verifies(Vector, out _), Is.False);

        [TestCaseSource(nameof(PriceStatements))]
        public void A_price_statement_and_its_digest(JObject Vector)
        {

            Assert.That(RoamingNetworkPriceStatement.TryParse(Text(Vector, "statement"), out var statement, out var error), Is.True, error);
            Assert.That(statement!.Digest, Is.EqualTo(Text(Vector, "digest")));

        }

        [TestCaseSource(nameof(TrustAnchors))]
        public void A_trust_anchor_and_its_QR_code(JObject Vector)

            => HistoryTests.CheckTrustAnchor(Text(Vector, "qrCode"), Vector, CanonicalJSON.Serialize(POIJSONReader.Read(Text(Vector, "json"))));

    }

}
