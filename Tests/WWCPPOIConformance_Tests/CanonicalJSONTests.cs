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

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// poi-canonical-json.json: JSON text read as POI reads what it hashes, written as the canonical JSON and the
    /// deterministic CBOR of Styx; and JSON text a reader must refuse.
    /// </summary>
    [TestFixture]
    public class CanonicalJSONTests
    {

        public static IEnumerable<TestCaseData> Vectors()        => VectorFiles.Cases(VectorFiles.CanonicalJSON, "vectors");
        public static IEnumerable<TestCaseData> InvalidInputs()  => VectorFiles.Cases(VectorFiles.CanonicalJSON, "invalidInputs");


        [Test]
        public void VectorsAreLoaded()
        {
            using (Assert.EnterMultipleScope())
            {
                Assert.That(Vectors().Count(),        Is.GreaterThanOrEqualTo(50));
                Assert.That(InvalidInputs().Count(),  Is.GreaterThanOrEqualTo(20));
            }
        }


        [TestCaseSource(nameof(Vectors))]
        public void Writes_canonical_JSON_and_deterministic_CBOR(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            var token     = POIJSONReader.Read(Vector["input"]!.Value<String>()!);
            var expected  = (JObject) Vector["expected"]!;

            using (Assert.EnterMultipleScope())
            {

                Assert.That(CanonicalJSON.Serialize(token), Is.EqualTo(expected["canonical"]!.Value<String>()));

                if (expected["cborHex"] is JToken cbor)
                    Assert.That(Convert.ToHexStringLower(CBORJSON.ToCBOR(CanonicalJSON.ToUTF8Bytes(token).AsSpan()).ToByteArray(CBORWriterOptions.Canonical)),
                                Is.EqualTo(cbor.Value<String>()));

            }

        }


        [TestCaseSource(nameof(InvalidInputs))]
        public void Refuses_what_is_no_JSON_to_hash(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            var input = Vector["input"]!.Value<String>()!;

            if (VectorFiles.Deviates(Vector))
            {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                Assert.DoesNotThrow(() => POIJSONReader.Read(input), "The known deviation is gone: remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
                return;
            }

            var read = (JToken?) null;

            Assert.That(() => read = POIJSONReader.Read(input),
                        Throws.Exception,
                        () => $"Taken as {read?.ToString(Newtonsoft.Json.Formatting.None) ?? "?"}, canonical: {(read is null ? "?" : CanonicalJSON.Serialize(read))}");

        }

    }


    /// <summary>
    /// poi-encodings.json: Base64 as POI reads keys and signature values - canonical, which WWCP_POI3 checks at every
    /// place by the round trip Convert.ToBase64String(Convert.FromBase64String(text)) == text, there being no shared
    /// helper - and Base45 of Styx, as the QR code of a trust anchor holds its CBOR.
    /// </summary>
    [TestFixture]
    public class EncodingTests
    {

        public static IEnumerable<TestCaseData> Base64()         => VectorFiles.Cases(VectorFiles.Encodings, "base64");
        public static IEnumerable<TestCaseData> Base64Invalid()  => VectorFiles.Cases(VectorFiles.Encodings, "base64Invalid");
        public static IEnumerable<TestCaseData> Base45()         => VectorFiles.Cases(VectorFiles.Encodings, "base45");
        public static IEnumerable<TestCaseData> Base45Invalid()  => VectorFiles.Cases(VectorFiles.Encodings, "base45Invalid");


        private static Byte[]? CanonicalBase64(String Text)
        {
            try
            {
                var bytes = Convert.FromBase64String(Text);
                return Convert.ToBase64String(bytes) == Text ? bytes : null;
            }
            catch (FormatException)
            {
                return null;
            }
        }


        [TestCaseSource(nameof(Base64))]
        public void Reads_Base64(JObject Vector)

            => Assert.That(Convert.ToHexStringLower(CanonicalBase64(Vector["text"]!.Value<String>()!) ?? []),
                           Is.EqualTo(Vector["hex"]!.Value<String>()));

        [TestCaseSource(nameof(Base64Invalid))]
        public void Refuses_Base64(JObject Vector)

            => Assert.That(CanonicalBase64(Vector["text"]!.Value<String>()!), Is.Null);

        [TestCaseSource(nameof(Base45))]
        public void Reads_and_writes_Base45(JObject Vector)
        {

            var text = Vector["text"]!.Value<String>()!;
            var hex  = Vector["hex"]!.Value<String>()!;

            using (Assert.EnterMultipleScope())
            {
                Assert.That(text.TryParseBASE45(out var bytes, out var error),  Is.True, error);
                Assert.That(Convert.ToHexStringLower(bytes ?? []),              Is.EqualTo(hex));
                Assert.That(Convert.FromHexString(hex).ToBase45(),              Is.EqualTo(text));
            }

        }

        [TestCaseSource(nameof(Base45Invalid))]
        public void Refuses_Base45(JObject Vector)

            => Assert.That(Vector["text"]!.Value<String>()!.TryParseBASE45(out _, out _), Is.False);

    }

}
