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

#endregion

namespace cloud.charging.open.protocols.WWCP.POI.Conformance.tests
{

    /// <summary>
    /// The steps of a replay (poi-history.json, poi-histories.json): the history takes each one, or refuses it, and says why.
    /// The replay checks the content; who may sign commits and checkpoints is the verifier's business, not its, so their
    /// signatures are taken unchecked.
    /// </summary>
    internal static class Replay
    {

        /// <summary>
        /// Take one step of a replay, its document given by DocumentOf.
        /// </summary>
        /// <param name="History">The history before the step, and after it.</param>
        /// <param name="Step">The step.</param>
        /// <param name="DocumentOf">The document of a step that takes one.</param>
        /// <param name="Error">Why the step was refused, or the head is not the one expected.</param>
        public static Boolean TryStep(ref RoamingNetworkHistory?  History,
                                      JObject                     Step,
                                      Func<JObject, JToken>       DocumentOf,
                                      out String?                 Error)
        {

            String Text  (String Name) => Step[Name]!.Value<String>()!;
            UInt64 Number(String Name) => Step[Name]!.Value<UInt64>();

            var op = Text("op");

            if (op != "fromSnapshot" && History is null)
            {
                Error = "A replay starts with a snapshot!";
                return false;
            }

            switch (op)
            {

                case "fromSnapshot":
                    return RoamingNetworkHistory.TryFromSnapshot((JObject) DocumentOf(Step), out History, out Error);

                case "append":
                    var commits = DocumentOf(Step);
                    foreach (var json in commits is JArray array ? array.Cast<JObject>() : [ (JObject) commits ])
                    {

                        if (!RoamingNetworkCommit.TryParse(json, out var commit, out Error))
                            return false;

                        if (!History!.TryAppend(commit, out Error, VerifyCommitSignature: (_, _) => true))
                        {
                            Error = $"Revision {commit.Revision}: {Error}";
                            return false;
                        }

                    }
                    Error = null;
                    return true;

                case "takeCheckpoint":
                    if (!RoamingNetworkCheckpoint.TryParse((JObject) DocumentOf(Step), out var checkpoint, out Error))
                        return false;
                    if (!History!.TryAddCheckpoint(checkpoint, out Error, VerifyCheckpointSignature: (_, _) => true))
                    {
                        Error = $"Checkpoint {checkpoint.Sequence}: {Error}";
                        return false;
                    }
                    return true;

                case "startNextEpoch":
                    if (!History!.TryStartNextEpoch(out var next, out Error))
                        return false;
                    History = next;
                    if (History.Root.Id.ToString() != Text("genesisCommitId"))
                    {
                        Error = $"The genesis of the epoch {History.Epoch.Number} is '{History.Root.Id}', not '{Text("genesisCommitId")}'!";
                        return false;
                    }
                    return true;

                case "expectHead":
                    var head   = History!.Head;
                    var eTags  = head.RoamingNetwork.CalcETags().Select(eTag => eTag.ToString()).ToArray();
                    Error      = History.Epoch.Number       != Number("epoch")     ? $"The head is of the epoch {History.Epoch.Number}, not {Number("epoch")}!"
                               : head.Commit.Revision       != Number("revision")  ? $"The head has the revision {head.Commit.Revision}, not {Number("revision")}!"
                               : head.Commit.Id.ToString()  != Text("commitId")    ? $"The head is '{head.Commit.Id}', not '{Text("commitId")}'!"
                               : Step["eTags"] is JArray && !eTags.SequenceEqual(VectorFiles.Strings(Step, "eTags"))
                                                                                    ? $"The head has the ETags {String.Join(", ", eTags)}!"
                               : null;
                    return Error is null;

                default:
                    throw new InvalidOperationException($"The replay step '{op}' is not known to this harness: the vector files are newer than the harness!");

            }

        }

    }

}
