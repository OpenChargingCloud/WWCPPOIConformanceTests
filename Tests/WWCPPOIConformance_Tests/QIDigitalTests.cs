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
    /// poi-qidigital.json: the QI-Digital documents example A14 published in the frozen run, the papers of the meter of
    /// DE*GEF*E2*1, checked as example A14 checks them: each against QA, the declaration against the certificates it
    /// names, the certificates covering a meter - and refused, each refusal with its control.
    /// </summary>
    [TestFixture]
    public class QIDigitalTests
    {

        public static IEnumerable<TestCaseData> Vectors()  => VectorFiles.Cases(VectorFiles.QIDigital, "vectors");


        [Test]
        public void VectorsAreLoaded()
        {
            Assert.That(Vectors().Count(), Is.GreaterThanOrEqualTo(1));
        }


        /// <summary>
        /// A document of a case: of the run with a JSON patch, or given as JSON text, read as POI reads JSON.
        /// </summary>
        private static JObject DocumentOf(JObject Reference)
            => (JObject) (Reference["text"] is JToken text
                              ? POIJSON.Read(text.Value<String>()!)
                              : VectorFiles.Patched(Reference));

        /// <summary>
        /// The roaming network of a case, which must read: it is no document under test.
        /// </summary>
        private static RoamingNetwork NetworkOf(JObject Case)
            => RoamingNetwork.TryParse(DocumentOf((JObject) Case["network"]!), out var network, out var error)
                   ? network
                   : throw new InvalidOperationException($"The roaming network of the case does not read: {error}");

        /// <summary>
        /// The certificate of conformity a declaration is checked against, which must read: it is no document under test.
        /// </summary>
        private static DigitalCertificateOfConformity CertificateOf(JObject Case)
            => DigitalCertificateOfConformity.TryParse(DocumentOf((JObject) Case["certificate"]!), out var certificate, out var error)
                   ? certificate
                   : throw new InvalidOperationException($"The certificate of conformity of the case does not read: {error}");

        /// <summary>
        /// The energy meter of the EVSE a case names, as its roaming network names it at runtime, as a QI-Digital item.
        /// </summary>
        private static QIDigitalItem MeterOf(JObject Case)
        {

            var network = NetworkOf(Case);

            if (!network.TryGetChargingStationOperatorById(ChargingStationOperator_Id.Parse(Case["chargingStationOperatorId"]!.Value<String>()!), out var chargingStationOperator) ||
                !chargingStationOperator.TryGetEffectiveEVSE(EVSE_Id.Parse(Case["evseId"]!.Value<String>()!), out var evse) ||
                 evse.EnergyMeter is null)
            {
                throw new InvalidOperationException($"The roaming network of the case has no energy meter of the EVSE '{Case["evseId"]}'!");
            }

            return QIDigitalItem.Of(evse.EnergyMeter);

        }


        /// <summary>
        /// Check the document of the given case as the vector says (SPECIFICATION.md does not hold the QI-Digital
        /// documents; example A14 and WWCP_POI3/RoamingNetwork/QIDigital do): read, then verified against the roaming
        /// network at the time of the case, checked against the certificate of the case, or covering the meter of the case.
        /// </summary>
        private static Boolean TryCheck(JObject Vector, JObject Case, out String? Error)
        {

            var kind      = Vector["kind"]!. Value<String>();
            var check     = Vector["check"]!.Value<String>();
            var document  = DocumentOf((JObject) Case["document"]!);

            switch (check)
            {

                case "verify":
                    var network  = NetworkOf(Case);
                    var at       = HistoryTests.Time(Case["at"]!.Value<String>()!);
                    return kind switch {
                               "certificateOfConformity"  => DigitalCertificateOfConformity.TryParse(document, out var certificate, out Error) && certificate.TryVerify(network, out Error, at),
                               "declarationOfConformity"  => DigitalDeclarationOfConformity.TryParse(document, out var declaration, out Error) && declaration.TryVerify(network, out Error, at),
                               "calibrationCertificate"   => DigitalCalibrationCertificate. TryParse(document, out var calibration, out Error) && calibration.TryVerify(network, out Error, at),
                               _                          => throw new InvalidOperationException($"A QI-Digital document of the kind '{kind}' is not known to this harness: the vector files are newer than the harness!")
                           };

                // The declaration against a certificate it names: no signature is looked at, the certificate's own check
                // tells whether it is valid.
                case "certificate":
                    return DigitalDeclarationOfConformity.TryParse(document, out var named, out Error) &&
                           named.TryVerify(CertificateOf(Case), out Error);

                case "cover":
                    return DigitalCertificateOfConformity.TryParse(document, out var covering, out Error) &&
                           covering.TryCover(MeterOf(Case), out Error);

                default:
                    throw new InvalidOperationException($"The QI-Digital check '{check}' is not known to this harness: the vector files are newer than the harness!");

            }

        }


        [TestCaseSource(nameof(Vectors))]
        public void A_QI_Digital_document_checked_as_example_A14_checks_it(JObject Vector)
        {

            VectorFiles.SkipUnlessApplicable(Vector);

            String? error;

            if (Vector["expected"]!.Value<String>() == "accepted")
            {
                Assert.That(TryCheck(Vector, Vector, out error), Is.True, error);
                return;
            }

            // The control: the same check of the documents of the run, against QA as published, taken.
            var control = (JObject) (Vector["control"] ?? throw new InvalidOperationException($"The refusal {Vector["id"]} names no control!"));
            Assert.That(TryCheck(Vector, control, out error), Is.True, () => $"The control is refused: {error}");

            var taken = TryCheck(Vector, Vector, out error);

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
