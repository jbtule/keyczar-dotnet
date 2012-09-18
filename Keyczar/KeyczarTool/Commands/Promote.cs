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
using ManyConsole;

namespace KeyczarTool
{
    public class Promote : ConsoleCommand
    {
        private string _location;
        private int _version;

        public Promote()
        {
            this.IsCommand("promote", "Promote a given key version from the key set.");
            this.HasRequiredOption("l|location=", "The location of the key set.", v => { _location = v; });
            this.HasRequiredOption("v|version=", "The key version.", v => { _version = int.Parse(v); });
            this.SkipsCommandSummaryBeforeRunning();
        }
        public override int Run(string[] remainingArguments)
        {
            using (var keySet = new MutableKeySet(_location))
            {
                var status =keySet.Promote(_version);
                if (status == null)
                {
                    Console.WriteLine("Unknown Version {0}",_version);
                    return -1;
                }

                if (keySet.Save(new KeySetWriter(_location, overwrite:true)))
                {
                    Console.WriteLine("Promoted Version {0} to {1} ",_version,status);
                    return 0;
                } 
                
                Console.WriteLine("Could not write file to {0}", _location);
                return -1;
            }
        }
    }
}
