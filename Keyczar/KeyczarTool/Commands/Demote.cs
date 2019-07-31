// Copyright 2012 James Tuley (jay+code@tuley.name)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using ManyConsole.CommandLineUtils;

namespace KeyczarTool
{
    public class Demote : ConsoleCommand
    {
        private string _location;
        private int _version;

        public Demote()
        {
            this.IsCommand("demote", Localized.Demote);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasRequiredOption("v|version=", Localized.Version, v => { _version = int.Parse(v); });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            using (var keySet = new MutableKeySet(_location))
            {
                var status = keySet.Demote(_version);
                if (status == null)
                {
                    Console.WriteLine("{0} {1}", Localized.MsgUnknownVersion, _version);
                    return -1;
                }
                try
                {
                    if (keySet.Save(new FileSystemKeySetWriter(_location, overwrite: true)))
                    {
                        Console.WriteLine(Localized.MsgDemotedVersion, _version, status);
                        return 0;
                    }
                }
                catch
                {
                }
            }

            Console.WriteLine("{0} {1}", Localized.MsgCouldNotWrite, _location);
            return -1;
        }
    }
}