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
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using ManyConsole;
using Keyczar.Util;

namespace KeyczarTool
{
    public class UseKey : ConsoleCommand
    {
        private string _location;
        private string _crypterLocation;
        private string _message;
        private bool _file;
        private string _destination;
        private bool _binary;

        public UseKey()
        {
            this.IsCommand("usekey", "Uses keyset to encrypt or sign a message.");
            this.HasRequiredOption("l|location=", "The location of the key set.", v => { _location = v; });
            this.HasOption("c|crypter=", "The crypter key set location.", v => { _crypterLocation = v; });
            this.HasOption("m|message=", "The message (uses std in if not set).", v => { _message = v; });
            this.HasOption("d|destination=", "The output destination.", v => { _destination = v; });
            this.HasOption("f|file", "The message is a file location", v => { _file = true; });
            this.HasOption("b|binary", "Specifies binary output.", v => { _binary = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }


        public override int Run(string[] remainingArguments)
        {

            using (var keycrypter = String.IsNullOrWhiteSpace(_crypterLocation) ? null :  new Crypter(_crypterLocation))
            {

                IKeySet ks = new KeySet(_location);
                if (!String.IsNullOrWhiteSpace(_crypterLocation))
                {

                    ks = new EncryptedKeySet(ks, keycrypter);
                }

                    Stream inStream;
                    if (String.IsNullOrWhiteSpace(_message))
                    {
                        inStream = Console.OpenStandardInput();
                    }else if (_file)
                    {
                        inStream = File.OpenRead(_message);
                    }else
                    {
                        inStream = new MemoryStream(Keyczar.Keyczar.DefaultEncoding.GetBytes(_message));
                    }



                Stream outstream;
                if (_binary)
                    {
                       if (String.IsNullOrWhiteSpace(_destination))
                       {
                           outstream = Console.OpenStandardOutput();
                       }else
                       {
                           outstream = File.Open(_destination, FileMode.CreateNew);
                       }
                    }else
                {
                    outstream = new MemoryStream();
                }



                using(inStream)
                using(outstream)
                {
                    if(ks.Metadata.Purpose == KeyPurpose.DECRYPT_AND_ENCRYPT
                        || ks.Metadata.Purpose == KeyPurpose.ENCRYPT )
                    {
                        using (var crypter =  new Crypter(ks))
                        {
                            crypter.Encrypt(inStream, outstream);
                        }
                    }else
                    {
                        using (var signer = new Signer(ks))
                        {
                            var sig = signer.Sign(inStream);
                            outstream.Write(sig,0,sig.Length);
                        }
                    }

                    if (!_binary)
                    {
                        var memstream = (MemoryStream) outstream;
                        outstream.Flush();
                        var encodedOutput = WebSafeBase64.Encode(memstream.ToArray());
                        
                        if (String.IsNullOrWhiteSpace(_destination))
                        {
                            Console.Write(encodedOutput);
                        }
                        else
                        {
                            if(File.Exists(_destination))
                                throw new Exception("File already Exists!!");
                            File.WriteAllText(_destination, new string(encodedOutput));
                        }
                    }
                    
                }
            }

            return 0;
        }
    }
}
