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
using Keyczar.Util;
using ManyConsole;

namespace KeyczarTool
{
    public class PubKey : ConsoleCommand
    {
        private string _location;
        private string _destination;
        private string _crypterLocation;
        private bool _password;

        public PubKey()
        {
            this.IsCommand("pubkey", Localized.PubKey);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasRequiredOption("d|destination=", Localized.Destination, v => { _destination = v; });
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new FileSystemKeySet(_location);

            Func<string> prompt = CachedPrompt.Password(Util.PromptForPassword).Prompt;

            IDisposable dks = null;
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                if (_password)
                {
                    var cks = KeySet.LayerSecurity(FileSystemKeySet.Creator(_crypterLocation),
                                                   PbeKeySet.Creator(prompt)
                                                  );
                    crypter = new Crypter(cks);
                    dks = cks;
                }
                else
                {
                    crypter = new Crypter(_crypterLocation);
                }
                ks = new EncryptedKeySet(ks, crypter);
            }
            else if (_password)
            {
                ks = new PbeKeySet(ks, prompt);
            }
            var d2ks = ks as IDisposable;


            using (crypter)
            using (dks)
            using (d2ks)
            using (var keySet = new MutableKeySet(ks))
            {
                var pubKeySet = keySet.PublicKey();
                if (pubKeySet != null)
                {
                    using (pubKeySet)
                    {
                        IKeySetWriter writer = new FileSystemKeySetWriter(_destination, overwrite: false);

                        if (pubKeySet.Save(writer))
                        {
                            Console.WriteLine(Localized.MsgNewPublicKeySet);
                            ret = 0;
                        }
                        else
                        {
                            ret = -1;
                        }
                    }
                }
                else
                {
                    ret = -1;
                }
            }

            return ret;
        }
    }
}