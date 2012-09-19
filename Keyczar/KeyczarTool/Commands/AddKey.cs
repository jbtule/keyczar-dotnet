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
    class AddKey : ConsoleCommand
    {
        private string _location;
        private KeyStatus _status;
        private int _size;
        private string _crypterLocation;
        private string _padding;
        private bool _password;

        public AddKey()
        {
            this.IsCommand("addkey", "Add a new key to an existing key set.");
            this.HasRequiredOption("l|location=", "The location of the key set.", v => { _location = v; });
			this.HasRequiredOption("s|status=", "The status (active|primary).", v => { _status = v; });
            this.HasOption<int>("b|size=", "The key size in bits.", v => { _size = v; });
            this.HasOption("c|crypter=", "The crypter key set location.", v => { _crypterLocation = v; });
            this.HasOption("p|password", "Password for decrypting the key.", v => { _password = true; });
            this.HasOption("g|padding=", "RSA Padding (oaep|pkcs).", v => { _padding = v; });
            this.SkipsCommandSummaryBeforeRunning();
        }


        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new KeySet(_location);

			var prompt = ks.Metadata.Encrypted 
				 ? new Func<string>(CachedPrompt.Password(Util.PromptForPassword).Prompt)
				 : new Func<string>(CachedPrompt.Password(Util.DoublePromptForPassword).Prompt);

            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                crypter = new Crypter(_crypterLocation);
                ks = new EncryptedKeySet(ks, crypter);
            }else if (_password)
            {
				ks = new PbeKeySet(ks, prompt);

            }

            using (var keySet = new MutableKeySet(ks))
            {
                 if(_status != KeyStatus.PRIMARY && _status != KeyStatus.ACTIVE)
                 {
                     Console.WriteLine("Invalid status:{0}",_status.Identifier);
                     return -1;
                 }

                var ver = keySet.AddKey(_status, _size);
                if (!String.IsNullOrWhiteSpace(_padding))
                {
                    var key =keySet.GetKey(ver);
                    ((dynamic)key).Padding = _padding;
                }

                IKeySetWriter writer = new KeySetWriter(_location, overwrite:true);

                if (crypter != null)
                {
                    writer = new EncryptedKeySetWriter(writer,crypter);
                }else if(_password){
					writer = new PbeKeySetWriter(writer, prompt);

				}
                using (writer as IDisposable)
                {
                    if (keySet.Save(writer))
                    {
                        Console.WriteLine("Created new key version:{0}", ver);
                        ret = 0;
                    }
                    else
                    {
                        ret = -1;

                    }
                }
            }

            if(crypter !=null)
                crypter.Dispose();

            return ret;
        }
    }
}
