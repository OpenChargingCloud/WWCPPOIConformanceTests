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
    /// The golden vector files (test-vectors/poi-*.json) and the documents of the frozen run they name, read as the
    /// implementation reads JSON it hashes: POIJSON.Read of WWCP_POI3 (SPECIFICATION.md, section 1), which keeps decimals
    /// as written, strings as strings, and refuses a property named twice and a number a decimal can not hold.
    /// </summary>
    public static class VectorFiles
    {

        /// <summary>
        /// The name this harness (and its implementation under test) is known by within the vector files
        /// ("knownDeviations", "notApplicable").
        /// </summary>
        public const String ImplementationName = "wwcp-poi3";

        /// <summary>
        /// The optional capabilities WWCP_POI3 provides ("requires" of vectors).
        /// </summary>
        public static readonly IReadOnlySet<String> Capabilities = new HashSet<String> {
            "signing"
        };

        /// <summary>
        /// Every capability name the vector format knows: a vector requiring anything else means the vector files are
        /// newer than this harness - fail, never skip silently.
        /// </summary>
        public static readonly IReadOnlySet<String> KnownCapabilities = new HashSet<String> {
            "signing"
        };


        #region RepositoryRoot / VectorsDirectory / RunDirectory

        /// <summary>
        /// The repository root, found by walking up from the test assembly to the solution file - stable however the
        /// test host is started.
        /// </summary>
        public static DirectoryInfo RepositoryRoot { get; } = FindRepositoryRoot();

        private static DirectoryInfo FindRepositoryRoot()
        {

            var directory = new DirectoryInfo(AppContext.BaseDirectory);

            while (directory is not null &&
                  !File.Exists(Path.Combine(directory.FullName, "WWCPPOIConformanceTests.slnx")))
            {
                directory = directory.Parent;
            }

            return directory
                       ?? throw new InvalidOperationException("Could not locate the repository root!");

        }

        public static String VectorsDirectory  => Path.Combine(RepositoryRoot.FullName, "test-vectors");

        public static String RunDirectory      => Path.Combine(VectorsDirectory, History["run"]!.Value<String>()!.Replace('/', Path.DirectorySeparatorChar));

        #endregion


        public static JObject CanonicalJSON  { get; } = Load("poi-canonical-json.json");
        public static JObject Encodings      { get; } = Load("poi-encodings.json");
        public static JObject Specification  { get; } = Load("poi-specification.json");
        public static JObject Trust          { get; } = Load("poi-trust.json");
        public static JObject History        { get; } = Load("poi-history.json");
        public static JObject Refusals       { get; } = Load("poi-refusals.json");
        public static JObject Histories      { get; } = Load("poi-histories.json");


        private static JObject Load(String FileName)

            => (JObject) POIJSON.Read(File.ReadAllText(Path.Combine(VectorsDirectory, FileName)));


        #region Cases(File, ListName)

        /// <summary>
        /// The vectors of the given list of a vector file, as test cases named by their ids.
        /// </summary>
        public static IEnumerable<TestCaseData> Cases(JObject File, String ListName)

            => ((JArray) (File[ListName] ?? throw new InvalidOperationException($"The vector file has no list '{ListName}'!"))).
                   Cast<JObject>().
                   Select(vector => new TestCaseData(vector).
                                        SetArgDisplayNames(vector["id"]!.Value<String>()!).
                                        SetDescription(vector["description"]?.Value<String>() ?? ""));

        #endregion


        #region Applicability

        /// <summary>
        /// Skips the vector when this implementation lacks a capability it requires, or when it does not apply here.
        /// </summary>
        public static void SkipUnlessApplicable(JObject Vector)
        {

            var requires = Strings(Vector, "requires");

            foreach (var capability in requires)
                if (!KnownCapabilities.Contains(capability))
                    Assert.Fail($"The vector requires the capability '{capability}' this harness does not know: the vector files are newer than the harness!");

            var missing = requires.Where(capability => !Capabilities.Contains(capability)).ToArray();

            if (missing.Length > 0)
                Assert.Ignore($"Requires {String.Join(", ", missing)}, which {ImplementationName} does not provide.");

            if (Strings(Vector, "notApplicable").Contains(ImplementationName))
                Assert.Ignore($"Not applicable to {ImplementationName}.");

        }

        /// <summary>
        /// Whether this implementation is known to deviate from the vector: it is then held to its deviation.
        /// </summary>
        public static Boolean Deviates(JObject Vector)

            => Strings(Vector, "knownDeviations").Contains(ImplementationName);

        public static String[] Strings(JObject Vector, String Name)

            => Vector[Name] is JArray array
                   ? [ .. array.Select(item => item.Value<String>()!) ]
                   : [];

        #endregion


        #region Documents of the run: RunText(File) / RunDocument(File, Pointer) / Patched(Document)

        public static String RunText(String File)

            => System.IO.File.ReadAllText(Path.Combine(RunDirectory, File.Replace('/', Path.DirectorySeparatorChar)));

        /// <summary>
        /// A document of the frozen run, read as POI reads JSON: the file and a JSON pointer (RFC 6901) into it.
        /// </summary>
        public static JToken RunDocument(String File, String Pointer = "")

            => Resolve(POIJSON.Read(RunText(File)), Pointer, File).DeepClone();

        public static JToken RunDocument(JObject Reference)

            => RunDocument(Reference["file"]!.Value<String>()!, Reference["pointer"]?.Value<String>() ?? "");

        /// <summary>
        /// A document of the run with a JSON patch (RFC 6902: add, replace, remove) applied.
        /// </summary>
        public static JToken Patched(JObject Reference)
        {

            var document = RunDocument(Reference);

            foreach (var operation in ((JArray) Reference["patch"]!).Cast<JObject>())
            {

                var op       = operation["op"]!.Value<String>()!;
                var tokens   = Tokens(operation["path"]!.Value<String>()!);
                var last     = tokens[^1];
                var parent   = tokens[..^1].Aggregate(document, (value, token) => Step(value, token, Reference["file"]!.Value<String>()!));
                var value    = operation["value"]?.DeepClone();

                switch (parent)
                {

                    case JArray array:
                        var index = last == "-" ? array.Count : Int32.Parse(last);
                        if      (op == "remove") array.RemoveAt(index);
                        else if (op == "add")    array.Insert(index, value!);
                        else                     array[index] = value!;
                        break;

                    case JObject obj:
                        if (op == "remove") obj.Remove(last);
                        else                obj[last] = value;
                        break;

                    default:
                        throw new InvalidOperationException($"The patch path '{operation["path"]}' names no container!");

                }

            }

            return document;

        }

        private static String[] Tokens(String Pointer)

            => Pointer.Length == 0
                   ? []
                   : [ .. Pointer[1..].Split('/').Select(token => token.Replace("~1", "/").Replace("~0", "~")) ];

        private static JToken Step(JToken Value, String Token, String Where)

            => (Value switch {
                   JArray  array  => Int32.TryParse(Token, out var index) && index < array.Count ? array[index] : null,
                   JObject obj    => obj[Token],
                   _              => null
               }) ?? throw new InvalidOperationException($"{Where}: the pointer names nothing at '{Token}'!");

        private static JToken Resolve(JToken Document, String Pointer, String Where)

            => Tokens(Pointer).Aggregate(Document, (value, token) => Step(value, token, Where));

        #endregion

    }

}
