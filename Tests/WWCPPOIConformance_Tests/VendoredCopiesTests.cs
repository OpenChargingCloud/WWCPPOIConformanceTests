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

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// WWCP_POI.TS carries a VENDORED COPY of the golden vector files and of the frozen run (tests/vectors/poi-*.json,
    /// tests/vectors/csharp-987fa26), so that its own test suite (tests/conformance.test.ts) runs against the very same
    /// bytes while staying self-contained.
    ///
    /// These tests fail when a vendored copy drifts from test-vectors/ of this repository. In CI that guards the pinned
    /// submodule; in the nightly run, which advances the submodules to their upstream HEADs, the upstream branch. Fix a
    /// drift by regenerating:
    ///
    ///     node tools/generate-test-vectors.mjs --mirror libs/WWCP_POI.TS/tests/vectors
    ///
    /// then commit WWCP_POI.TS first, and bump its pin here.
    /// </summary>
    [TestFixture]
    public class VendoredCopiesTests
    {

        private static readonly String[] vectorFiles = [
            "poi-canonical-json.json",
            "poi-encodings.json",
            "poi-specification.json",
            "poi-trust.json",
            "poi-history.json",
            "poi-refusals.json"
        ];

        private static String VendoredDirectory
            => Path.Combine(VectorFiles.RepositoryRoot.FullName, "libs", "WWCP_POI.TS", "tests", "vectors");


        [Test]
        public void The_frozen_run_is_vendored_byte_for_byte()
        {

            var run       = VectorFiles.RunDirectory;
            var vendored  = Path.Combine(VendoredDirectory, Path.GetFileName(run));

            if (!Directory.Exists(vendored))
                Assert.Fail($"WWCP_POI.TS vendors no copy of {Path.GetFileName(run)}: is the submodule checked out?");

            var ours      = Directory.GetFiles(run,      "*", SearchOption.AllDirectories).Select(file => Path.GetRelativePath(run,      file)).Order(StringComparer.Ordinal).ToArray();
            var theirs    = Directory.GetFiles(vendored, "*", SearchOption.AllDirectories).Select(file => Path.GetRelativePath(vendored, file)).Order(StringComparer.Ordinal).ToArray();

            Assert.That(theirs, Is.EqualTo(ours), "The vendored copy names other files");

            using (Assert.EnterMultipleScope())
            {
                foreach (var file in ours)
                    Assert.That(File.ReadAllBytes(Path.Combine(vendored, file)), Is.EqualTo(File.ReadAllBytes(Path.Combine(run, file))), file);
            }

        }


        [TestCaseSource(nameof(vectorFiles))]
        public void A_vector_file_is_vendored_byte_for_byte(String FileName)
        {

            var vendored = Path.Combine(VendoredDirectory, FileName);

            if (!File.Exists(vendored))
                Assert.Ignore($"This WWCP_POI.TS does not vendor {FileName}: its own suite does not run the golden vectors.");

            Assert.That(File.ReadAllBytes(vendored), Is.EqualTo(File.ReadAllBytes(Path.Combine(VectorFiles.VectorsDirectory, FileName))));

        }

    }

}
