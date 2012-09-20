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
            this.IsCommand("addkey", Localized.AddKey);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
			this.HasRequiredOption("s|status=", Localized.Status, v => { _status = v; });
            this.HasOption<int>("b|size=", Localized.Size, v => { _size = v; });
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.HasOption("g|padding=", Localized.Padding, v => { _padding = v; });
            this.SkipsCommandSummaryBeforeRunning();
        }


        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new KeySet(_location);

            Func<string> crypterPrompt = CachedPrompt.Password(Util.PromptForPassword).Prompt;

			var prompt = ks.Metadata.Encrypted 
				 ? new Func<string>(CachedPrompt.Password(Util.PromptForPassword).Prompt)
				 : new Func<string>(CachedPrompt.Password(Util.DoublePromptForPassword).Prompt);

            IDisposable dks = null;
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                if (_password)
                {
                    var cks = new PbeKeySet(_crypterLocation, crypterPrompt);
                    crypter = new Crypter(cks);
                    dks = cks;
                }
                else
                {     
                    crypter = new Crypter(_crypterLocation);
                }
                ks = new EncryptedKeySet(ks, crypter);
            }else  if (_password)
            {
                ks = new PbeKeySet(ks, prompt);
            }
            var d2ks = ks as IDisposable;


            using(crypter)
            using (dks)
            using (d2ks)
            using (var keySet = new MutableKeySet(ks))
            {
                 if(_status != KeyStatus.PRIMARY && _status != KeyStatus.ACTIVE)
                 {
                     Console.WriteLine("{0} {1}.",Localized.MsgInvalidStatus, _status.Identifier);
                     return -1;
                 }

                 object options = null;
                 if (!String.IsNullOrWhiteSpace(_padding))
                 {
                     options = new {Padding = _padding};
                 }

                 var ver = keySet.AddKey(_status, _size, options);
               

                IKeySetWriter writer = new KeySetWriter(_location, overwrite:true);
               
                if (crypter != null)
                {
                    writer = new EncryptedKeySetWriter(writer,crypter);
                }
                else if (_password)
                {
                    writer = new PbeKeySetWriter(writer, prompt);
                }

                using (writer as IDisposable)
                {
                    try
                    {
                        if (keySet.Save(writer))
                        {
                            Console.WriteLine("{0} {1}.",Localized.MsgCreatedKey, ver);
                            ret = 0;
                        }
                        else
                        {
                            ret = -1;
                        }
                    }
                    catch
                    {
                        ret = -1;
                    }
                }
            }

            if (ret != 0)
            {
                Console.WriteLine("{0} {1}.",Localized.MsgCouldNotWrite, _location);
            }

            return ret;
        }
    }
}
