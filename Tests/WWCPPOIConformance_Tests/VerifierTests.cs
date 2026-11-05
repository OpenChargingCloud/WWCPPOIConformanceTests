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
    /// poi-verifier.json: the verifier extensions of WWCP_POI.TS 0.2.0, which WWCP_POI3 has since WWCP_POI 89d2e02
    /// (WWCP_POI3/Verifier), of the fixtures of ChargyWebApp (runs/chargy-fc513cd) - experimental, no part of
    /// SPECIFICATION.md but for the usages chargeTransparencyRecords and witnessPublications.
    /// </summary>
    [TestFixture]
    public class VerifierTests
    {

        #region Documents of the fixtures

        /// <summary>
        /// A document of the fixtures, read as POI reads JSON: a file and a JSON pointer (RFC 6901) into it. Where the
        /// pointer goes on into a string, the string is a JSON document of its own (a fixture keeps signed decimals so).
        /// A file of the documents the generator makes is named with their directory, "documents" (e.g. "chargy",
        /// test-vectors/chargy); every other one is of the run of poi-verifier.json.
        /// </summary>
        internal static JToken ChargyDocument(JToken? Reference)
        {

            if (Reference is not JObject reference)
                throw new InvalidOperationException("The vector names no document!");

            var file       = reference["file"]!.Value<String>()!;
            var directory  = reference["documents"]?.Value<String>() is String documents
                                 ? Path.Combine(VectorFiles.VectorsDirectory, documents.Replace('/', Path.DirectorySeparatorChar))
                                 : VectorFiles.ChargyDirectory;
            var value      = POIJSON.Read(File.ReadAllText(Path.Combine(directory, file.Replace('/', Path.DirectorySeparatorChar))));

            foreach (var token in (reference["pointer"]?.Value<String>() ?? "") is { Length: > 0 } pointer
                                      ? pointer[1..].Split('/').Select(token => token.Replace("~1", "/").Replace("~0", "~"))
                                      : [])
            {
                if (value.Type == JTokenType.String)
                    value = POIJSON.Read(value.Value<String>()!);
                value = (value switch {
                            JArray  array  => Int32.TryParse(token, out var index) && index < array.Count ? array[index] : null,
                            JObject obj    => obj[token],
                            _              => null
                        }) ?? throw new InvalidOperationException($"{file}: the pointer names nothing at '{token}'!");
            }

            return value.Type == JTokenType.String && value.Value<String>()!.StartsWith('{')
                       ? POIJSON.Read(value.Value<String>()!)
                       : value.DeepClone();

        }

        private static String  Text (JToken? Reference) => ChargyDocument(Reference).Value<String>() ?? throw new InvalidOperationException("The document is no text!");
        private static DateTimeOffset Time(JToken? Value) => Value?.Type == JTokenType.String ? DateTimeOffset.Parse(Value.Value<String>()!, null, System.Globalization.DateTimeStyles.RoundtripKind) : throw new InvalidOperationException("The vector names no time as text!");
        private static String  Given(JToken? Value, String What) => Value?.Value<String>() ?? throw new InvalidOperationException($"The vector names no {What}!");

        private static T Ok<T>(Boolean Success, T? Value, String? ErrorResponse)
            => Success && Value is not null ? Value : throw new VerifierRefusal(ErrorResponse ?? "Unknown error!");

        /// <summary>
        /// What WWCP_POI3 refuses, with its words.
        /// </summary>
        internal sealed class VerifierRefusal(String Message) : Exception(Message);

        #endregion

        #region Trust and policies

        /// <summary>
        /// The local trust of a case: every identity key of its trust anchor trusted, of now or historical.
        /// </summary>
        private static IRoamingNetworkTrustAuthority TrustOf(JToken? Trust)
        {

            if (Trust is not JObject trust)
                throw new InvalidOperationException("The vector names no trust!");

            var anchor     = Ok(RoamingNetworkTrustAnchor.TryParse(Text(trust["anchor"]), out var a, out var error), a, error);
            var statement  = Ok(RoamingNetworkKeyStatement.TryParse((JObject) ChargyDocument(trust["keyStatement"]), out var s, out error), s, error);

            return trust["context"]?.Value<String>() == "historical"
                       ? Ok(HistoricalTrustContext.TryCreate(anchor, statement, anchor.Keys, out var historical, out error, Now: Time(trust["at"])), historical, error)
                       : Ok(RoamingNetworkTrustContext.TryCreate(anchor, statement, anchor.Keys, out var current, out error, At: Time(trust["at"])), current, error);

        }

        private static RoamingNetworkTrustContext CurrentTrustOf(JToken? Trust)
            => TrustOf(Trust) as RoamingNetworkTrustContext ?? throw new InvalidOperationException("The case needs a current trust context!");

        private static HistoricalPolicy PolicyOf(JToken? Policy)
        {

            if (Policy is not JObject policy)
                return new HistoricalPolicy();

            IReadOnlyList<TrustedWitness>? witnesses = null;
            if (policy["witnesses"] is JObject reference)
                witnesses = Ok(TrustedWitness.TryParseAll(ChargyDocument(reference), out var parsed, out var error), parsed, error);

            return new HistoricalPolicy(witnesses,
                                        policy["requiredWitnesses"]?.Value<UInt32>()   ?? 0,
                                        policy["requirePublication"]?.Value<Boolean>() ?? false);

        }

        private static WitnessPublicationPolicy? PublicationPolicyOf(JToken? Policy)
            => Policy?["publicationPolicy"] is JObject reference
                   ? Ok(WitnessPublicationPolicy.TryParse(ChargyDocument(reference), out var policy, out var error), policy, error)
                   : null;

        #endregion

        #region Results(Kind, Check)

        /// <summary>
        /// Check a case as the vector says, with the API of WWCP_POI3, and give what both implementations give of it,
        /// normalized: identifications, the words of the verdicts, counts. A refusal throws a VerifierRefusal.
        /// </summary>
        internal static JObject Results(String Kind, JObject Check)
        {

            var request = Check["request"] as JObject ?? [];

            switch (Kind)
            {

                case "meterKey":
                {
                    var proof = Ok(RoamingNetworkProof.TryParse((JObject) ChargyDocument(Check["proof"]), out var p, out var error), p, error);
                    var format = Given(request["keyFormat"], "key format") == "cose-key" ? MeasurementKeyFormat.COSEKey : MeasurementKeyFormat.SPKIDER;
                    var binding = Ok(VerifiedMeterKeyBinding.TryVerify(CurrentTrustOf(Check["trust"]), proof, Given(request["evseId"], "EVSE"), Given(request["meterSerialNumber"], "serial number"),
                                                                       format, out var b, out _, out error, request["meterId"]?.Value<String>(), request["keyId"]?.Value<String>()), b, error);
                    return new JObject(new JProperty("evseId",             binding.EVSEId),
                                       new JProperty("chargingStationId",  binding.ChargingStationId),
                                       new JProperty("meterId",            binding.MeterId),
                                       new JProperty("meterSerialNumber",  binding.MeterSerialNumber),
                                       new JProperty("keyId",              binding.Key.Id),
                                       new JProperty("keyIdScheme",        binding.Key.IdScheme),
                                       new JProperty("canonicalKeyId",     binding.Key.CanonicalId),
                                       new JProperty("association",        binding.Evidence.Association));
                }

                case "historicalMeterEvidence":
                {
                    var evidence = Ok(HistoricalMeterEvidence.TryParse(ChargyDocument(Check["evidence"]), out var e, out var error), e, error);
                    var format   = Given(request["keyFormat"], "key format") == "cose-key" ? MeasurementKeyFormat.COSEKey : MeasurementKeyFormat.SPKIDER;
                    var result   = Ok(evidence.TryVerify(TrustOf(Check["trust"]), Given(request["evseId"], "EVSE"), Given(request["meterSerialNumber"], "serial number"),
                                                         ((JArray) request["measurementTimes"]!).Select(Time), format, out var r, out error, PolicyOf(Check["policy"])), r, error);
                    return new JObject(new JProperty("bindings",         new JArray(result.Bindings.Select(binding => new JObject(new JProperty("meterId",     binding.MeterId),
                                                                                                                                  new JProperty("keyId",       binding.Key.Id),
                                                                                                                                  new JProperty("association", binding.Evidence.Association))))),
                                       new JProperty("publications",     new JArray(result.Versions.Select(version => version.Publication))),
                                       new JProperty("independentTime",  result.IndependentTime));
                }

                case "sessionPrice":
                {
                    var evidence = Ok(SessionPriceEvidence.TryParse(ChargyDocument(Check["evidence"]), out var e, out var error), e, error);
                    var result   = Ok(evidence.TryVerify(TrustOf(Check["trust"]), Given(request["evseId"], "EVSE"), Given(request["meterSerialNumber"], "serial number"),
                                                         Time(request["chargingStarted"]), Given(request["startDocumentSHA256"], "start document"), out var r, out error,
                                                         PolicyOf(Check["policy"]), PublicationPolicy: PublicationPolicyOf(Check["policy"])), r, error);
                    return new JObject(new JProperty("signatures",              result.Signatures),
                                       new JProperty("agreement",               result.Agreement),
                                       new JProperty("applicability",           result.Applicability),
                                       new JProperty("publication",             result.Publication),
                                       new JProperty("publicationBeforeStart",  result.PublicationBeforeStart),
                                       new JProperty("customerConsent",         result.CustomerConsent),
                                       new JProperty("witnessedBy",             new JArray(result.WitnessedBy)),
                                       new JProperty("selected",                result.Selected is null
                                                                                    ? JValue.CreateNull()
                                                                                    : new JObject(new JProperty("digest",        result.Selected.Digest),
                                                                                                  new JProperty("algorithm",     result.Selected.Statement.Algorithm),
                                                                                                  new JProperty("energyPerKWh",  result.Selected.Rates?.EnergyPerKWh))),
                                       new JProperty("organizations",           result.PublicationWitnesses is null
                                                                                    ? JValue.CreateNull()
                                                                                    : new JArray(result.PublicationWitnesses.Organizations)));
                }

                case "trustTransition":
                {
                    var transition = Ok(TrustTransition.TryParse(ChargyDocument(Check["transition"]), out var t, out var error), t, error);
                    var verified   = Ok(VerifiedTrustTransition.TryVerify(CurrentTrustOf(Check["trust"]), (JObject) ChargyDocument(Check["operator"]), transition, Time(Check["acceptedAt"]),
                                                                          RoamingNetworkEpoch.First, Check["sequence"]!.Value<Int32>(), out var v, out error), v, error);
                    return new JObject(new JProperty("requiredConsensus",  verified.Context.RequiredConsensus),
                                       new JProperty("signedByOld",        verified.SignedByOld.Length),
                                       new JProperty("signedByNext",       verified.SignedByNew.Length),
                                       new JProperty("policyId",           TrustTransition.PolicyIdOf(verified.Context.TrustAnchor)),
                                       new JProperty("epoch",              verified.Epoch.Number));
                }

                case "chargingDocumentKeys":
                {
                    var proof = Ok(RoamingNetworkProof.TryParse((JObject) ChargyDocument(Check["proof"]), out var p, out var error), p, error);
                    var keys  = Ok(AuthorizedChargingDocumentKeys.TryVerify(TrustOf(Check["trust"]), proof, Given(request["evseId"], "EVSE"), Given(request["operatorId"], "operator"),
                                                                            Time(request["at"]), out var k, out error), k, error);
                    return new JObject(new JProperty("chargingStationId",  keys.ChargingStationId),
                                       new JProperty("keys",               new JArray(keys.Keys.Select(key => new JObject(new JProperty("id",         key.Id),
                                                                                                                         new JProperty("algorithm",  key.Algorithm))))));
                }

                case "trustPolicyId":
                    return new JObject(new JProperty("policyId", TrustTransition.PolicyIdOf(Ok(RoamingNetworkTrustAnchor.TryParse(Text(Check["trustAnchor"]), out var anchor, out var anchorError), anchor, anchorError))));

                case "keyStatementDigest":
                    return new JObject(new JProperty("digest", TrustTransition.DigestOf(Ok(RoamingNetworkKeyStatement.TryParse((JObject) ChargyDocument(Check["keyStatement"]), out var statement, out var statementError), statement, statementError))));

                case "offerHashes":
                {
                    var (statementHash, tariffHash) = PricePublicationReceipt.OfferHashesOf((JObject) ChargyDocument(Check["priceStatement"]), (JObject) ChargyDocument(Check["tariff"]));
                    return new JObject(new JProperty("priceStatementSHA256", statementHash), new JProperty("tariffSHA256", tariffHash));
                }

                case "publicationReceipt":
                    return new JObject(new JProperty("digest", Ok(PricePublicationReceipt.TryParse(ChargyDocument(Check["receipt"]), out var receipt, out var receiptError), receipt, receiptError).Digest()));

                default:
                    throw new InvalidOperationException($"A verifier vector of the kind '{Kind}' is not known to this harness: the vector files are newer than the harness!");

            }

        }

        #endregion


        #region Vectors

        public static IEnumerable<TestCaseData> Vectors
            => VectorFiles.Cases(VectorFiles.Verifier, "vectors");

        /// <summary>
        /// An accepted vector gives what both implementations give of it; a refusal is refused, its control taken.
        /// </summary>
        [TestCaseSource(nameof(Vectors))]
        public void Verifier(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            var kind = Vector["kind"]!.Value<String>()!;

            if (Vector["expected"]!.Value<String>() == "accepted")
            {

                var result = Results(kind, Vector);

                if (VectorFiles.Deviates(Vector))
                {
                    // Pinned: the known deviation still holds. Once it gives the result, remove the marker in the generator.
                    Assert.That(JToken.DeepEquals(result, Vector["result"]), Is.False, "The known deviation is gone: remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
                    return;
                }

                Assert.That(JToken.DeepEquals(result, Vector["result"]), Is.True, $"WWCP_POI3 gives {result.ToString(Newtonsoft.Json.Formatting.None)}");
                return;

            }

            if (Vector["control"] is not JObject control)
            {
                Assert.Fail($"The refusal {Vector["id"]} names no control!");
                return;
            }

            // The control: the same check, of what the vector is about given otherwise, taken.
            Results(kind, control);

            if (VectorFiles.Deviates(Vector))
            {
                // Pinned: the known deviation still holds. Once it is refused, remove the marker in the generator.
                Assert.DoesNotThrow(() => Results(kind, Vector), "The known deviation is gone: remove the knownDeviations marker of the vector in tools/generate-test-vectors.mjs!");
                return;
            }

            var refusal = Assert.Throws<VerifierRefusal>(() => Results(kind, Vector));
            if (Vector["reason"]?.Value<String>() is String reason)
                Assert.That(refusal!.Message, Does.Contain(reason));

        }

        #endregion

    }

}
