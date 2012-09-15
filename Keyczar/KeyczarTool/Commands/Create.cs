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
using ManyConsole;
using NDesk.Options;
using Keyczar;
namespace KeyczarTool
{
    class Create : ConsoleCommand

    {
        private string _location;
        private string _pupose;
        private string _name;
        private bool _asymm;
        private string _asymmAlg;
        private bool _unofficial;
        private string _unoffAlg;

        public Create()
        {
            this.IsCommand("create", "Create a new key set.");
            this.HasRequiredOption("l|location=", "The location of the key set.", v => { _location = v; });
            this.HasRequiredOption("o|purpose=", "The purpose of the key set (sign|crypt).", v => { _pupose = v; });
            this.HasOption("n|name=", "The key set name.", v => { _name = v; });
            this.HasOption("a|asymmetric:", "Use asymmetric algorithm (dsa|rsa)", v => { _asymm = true;
                                                                                           _asymmAlg = v;
            });
            this.HasOption("u|unofficial:", "Use unofficial key type (aes_aead)", v =>
                                                                                      {
                                                                                          _unofficial = true;
                                                                                           _unoffAlg = v;
                                                                                      });
            this.SkipsCommandSummaryBeforeRunning();
        }
        
        public override int Run(string[] remainingArguments)
        {
            KeyPurpose purpose = _pupose == "sign" ? KeyPurpose.SIGN_AND_VERIFY : KeyPurpose.DECRYPT_AND_ENCRYPT;

            KeyType type = PickKeyType(purpose);


            var meta =new KeyMetadata()
                {
                    Name = _name,
                    Purpose = purpose,
                    Type = type,
                };
            using (var keySet = new MutableKeySet(meta))
            {

                if (keySet.Save(new KeySetWriter(_location)))
                {
                    Console.WriteLine("Created Key set. " + (_name ?? ""));
                    return 0;
                }
            }
            Console.WriteLine("Could not create key set at location:{0}", _location);

            return -1;
        }

        private KeyType PickKeyType(KeyPurpose purpose)
        {
            KeyType type;
            if (_asymm)
            {
                if (_asymmAlg == "rsa")
                {
                    type = KeyType.RSA_PRIV;
                }
                else
                {
                    if (purpose == KeyPurpose.DECRYPT_AND_ENCRYPT)
                    {
                        type = KeyType.RSA_PRIV;
                    }
                    else
                    {
                        type = KeyType.DSA_PRIV;
                    }
                }
            }
            else if (purpose == KeyPurpose.DECRYPT_AND_ENCRYPT)
            {
                if (_unofficial)
                {
                    type = KeyType.AES_AEAD;
                }
                else
                {
                    type = KeyType.AES;
                }
            }
            else
            {
                type = KeyType.HMAC_SHA1;
            }
            return type;
        }
    }
}
