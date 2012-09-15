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

        public static string TestDataPath(string baseDir, string topDir, string subDir =null)
        {
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
            get { return new KeyczarToolRunner(); }
        }

        internal class KeyczarToolRunner : DynamicObject
        {

			bool IsRunningOnMono = (Type.GetType ("Mono.Runtime") != null);

            public override bool TryInvoke(InvokeBinder binder, object[] args, out object result)
            {
                var stdInArgCount = binder.CallInfo.ArgumentCount - binder.CallInfo.ArgumentNames.Count;

                var stdInArgs = args.Take(stdInArgCount);

                var processArgs = args.Skip(stdInArgCount);

                var count = 0;
                var separateArgs = binder.CallInfo.ArgumentNames.Zip(processArgs,
                                                                     (n, p) =>
                                                                     count++ == 0
                                                                         ? n
                                                                         : p == null
                                                                               ? String.Format("--{0}", n)
                                                                               : string.Format("--{0}=\"{1}\"", n, p));


                var combinedArg = String.Join(" ", separateArgs);
				var program = "KeyczarTool";
				if(IsRunningOnMono){
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
					process.WaitForInputIdle(5000);
                    process.StandardInput.WriteLine(stdArg.ToString());
                }


                process.WaitForExit(5000);

                result = process.StandardOutput.ReadToEnd();
                Console.WriteLine(result);
				Console.WriteLine(process.StandardError.ReadToEnd());
                return true;
            }
        }
    }
}
