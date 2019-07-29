/*  Copyright 2012 James Tuley (jay+code@tuley.name)
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace KeyczarTest
{
    public static class Util
    {

        public static bool IsSizeTooSlow(int size)
        {
           return ((Environment.GetEnvironmentVariable("CI")?.Equals("true", StringComparison.InvariantCultureIgnoreCase)
              ?? false) && size > 5000);
        }
   

        public static string ReplaceDirPrefix(string prefixedDir)
        {
            prefixedDir = prefixedDir.Replace("gen|", Path.Combine("gen-testdata") + Path.DirectorySeparatorChar);
            prefixedDir = prefixedDir.Replace("rem|",
                                              Path.Combine("remote-testdata", "existing-data") +
                                              Path.DirectorySeparatorChar);
            return prefixedDir;
        }

        private static string TestDataBaseDir(string baseDir, [System.Runtime.CompilerServices.CallerFilePath] string sourceFilePath = "")
        {
            var dirPath = Path.GetDirectoryName(sourceFilePath);
            var testDir=  Path.Combine(dirPath, "..", "..", "TestData", baseDir);
            return Path.GetFullPath(testDir);
        }

        public static string TestDataPath(string baseDir, string topDir, string subDir = null)
        {
            baseDir = TestDataBaseDir(baseDir);


            if (String.IsNullOrWhiteSpace(topDir))
            {
                return baseDir;
            }

            return String.IsNullOrWhiteSpace(subDir)
                       ? Path.Combine(baseDir, topDir)
                       : Path.Combine(baseDir, subDir, topDir);
        }

        internal static dynamic KeyczarTool
        {
            get { return new InProcessKeyczarToolRunner(); }
        }
    }

    internal class NoArgFlag
    {
        public bool Show { get; }

        public NoArgFlag()
        {
            Show = true;
        }

        public NoArgFlag(bool show)
        {
            Show = show;
        }
    }

    internal class InProcessKeyczarToolRunner : KeyczarToolRunner
    {
        protected override void RunTool(out object result, IList<object> stdInArgs, IList<string> separateArgs)
        {
            byte[] stdinbytes;
            using (var instream = new MemoryStream())
            using (var tempwrite = new StreamWriter(instream))
            {
                if (stdInArgs.Any())
                {
                    foreach (var args in stdInArgs)
                    {
                        tempwrite.WriteLine(args);
                    }
                }
                tempwrite.Flush();
                stdinbytes = instream.ToArray();
            }


            var combinedArg = String.Join(" ", separateArgs);
            var program = "KeyczarTool";
            if (IsRunningOnMono)
            {
                combinedArg = "KeyczarTool.exe " + combinedArg;
                program = "mono";
            }

            Console.WriteLine("{0} {1}", program, combinedArg);
            var origIn = Console.In;
            var origOut = Console.Out;
            using (var inbyteStream = new MemoryStream(stdinbytes))
            using (var input = new StreamReader(inbyteStream))
            {
                Console.SetIn(input);
                using (var stream = new MemoryStream())
                using (var output = new StreamWriter(stream))
                {
                    Console.SetOut(output);
                    KeyczarTool.Program.Main(separateArgs.Select(it => it.Replace("\"", "")).ToArray());

                    output.Flush();
                    result = Encoding.UTF8.GetString(stream.ToArray());
                }

                Console.SetIn(origIn);
                Console.SetOut(origOut);
            }

            Console.WriteLine(result);
        }
    }

    internal class KeyczarToolRunner : DynamicObject
    {
        protected bool IsRunningOnMono = (Type.GetType("Mono.Runtime") != null);

        public override bool TryInvoke(InvokeBinder binder, object[] args, out object result)
        {
            var stdInArgCount = binder.CallInfo.ArgumentCount - binder.CallInfo.ArgumentNames.Count;

            var stdInArgs = args.Take(stdInArgCount);

            var processArgs = args.Skip(stdInArgCount);

            var count = 0;

            string resultSelector(string n, object p)
            {
                switch (count++)
                {
                    case 0:
                        return n;
                    default:
                        switch (p)
                        {
                            case null:
                                return $"--{n}";
                            case NoArgFlag x:
                                if (x.Show)
                                    return $"--{n}";
                                else
                                    return null;
                                    
                            default:
                                if (n.Equals("additionalArgs"))
                                    return String.Join(" ", ((string[]) p).Select(i => $"\"{i}\""));
                                else return $"--{n}=\"{p}\"";
                        }
                }
            }

            var separateArgs = binder.CallInfo.ArgumentNames.Zip(processArgs,
                                                                 resultSelector)
                                     .Where(it=>!String.IsNullOrEmpty(it))
                                     .ToList();


            RunTool(out result, stdInArgs.ToList(), separateArgs.ToList());

            return true;
        }

        protected virtual void RunTool(out object result, IList<object> stdInArgs, IList<string> separateArgs)
        {
            var combinedArg = String.Join(" ", separateArgs);
            var program = "KeyczarTool";
            if (IsRunningOnMono)
            {
                combinedArg = "KeyczarTool.exe " + combinedArg;
                program = "mono";
            }

            Console.WriteLine("{0} {1}", program, combinedArg);

            var process = new Process()
                              {
                                  StartInfo = new ProcessStartInfo(program, combinedArg)
                                                  {
                                                      RedirectStandardInput = true,
                                                      RedirectStandardOutput = true,
                                                      RedirectStandardError = true,
                                                      UseShellExecute = false,
                                                      CreateNoWindow = true
                                                  }
                              };
            process.Start();

            foreach (var stdArg in stdInArgs)
            {
                Thread.Sleep(3000);
                process.StandardInput.WriteLine(stdArg.ToString());
            }


            process.WaitForExit(5000);

            result = process.StandardOutput.ReadToEnd();
            Console.WriteLine(result);
            Console.WriteLine(process.StandardError.ReadToEnd());
        }
    }
}