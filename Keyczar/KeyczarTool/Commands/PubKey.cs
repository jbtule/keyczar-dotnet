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
    public class PubKey: ConsoleCommand
    {
        private string _location;
        private string _destination;
        private string _crypterLocation;

        public PubKey()
        {
            this.IsCommand("pubkey", "Extracts public keys to a new key set.");
            this.HasRequiredOption("l|location=", "The location of the private key set.", v => { _location = v; });
            this.HasRequiredOption("d|destination=", "The destination of the public key set.", v => { _destination = v; });
            this.HasOption("c|crypter=", "The location of the crypter to decrypt private key set.", v => { _crypterLocation = v; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new KeySet(_location);
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                crypter = new Crypter(_crypterLocation);
                ks = new EncryptedKeySet(ks, crypter);
            }

            using (var keySet = new MutableKeySet(ks))
            {
                var pubKeySet = keySet.PublicKey();
                if(pubKeySet !=null)
                {
                    using (pubKeySet)
                    {

                        IKeySetWriter writer = new KeySetWriter(_destination, overwrite: false);

                        if (crypter != null)
                        {
                            writer = new EncryptedKeySetWriter(writer, crypter);
                        }

                        if (pubKeySet.Save(writer))
                        {
                            Console.WriteLine("Created new public keyset");
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

            if (crypter != null)
                crypter.Dispose();

            return ret;
        }
    }
}
