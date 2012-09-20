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
        private bool _password;
		private bool _usecompression;
		string _compression;

        public UseKey()
        {
            this.IsCommand("usekey", Localized.UseKey);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.HasOption("m|message=", Localized.Message, v => { _message = v; });
            this.HasOption("d|destination=", Localized.Destination, v => { _destination = v; });
            this.HasOption("f|file", Localized.File, v => { _file = true; });
            this.HasOption("b|binary", Localized.Binary, v => { _binary = true; });
			this.HasOption("z|compression:", Localized.Compression, v => {_usecompression = true; _compression = v; });
            this.SkipsCommandSummaryBeforeRunning();
        }  


        public override int Run(string[] remainingArguments)
        {

            Crypter crypter = null;
            IKeySet ks = new KeySet(_location);
            Func<string> prompt = CachedPrompt.Password(Util.PromptForPassword).Prompt;

            IDisposable dks = null;
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                if (_password)
                {
                    var cks = new PbeKeySet(_crypterLocation, prompt);
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
            using (d2ks){

                    Stream inStream;
                    if (String.IsNullOrWhiteSpace(_message))
                    {
                        if (_password)
                        {
                            Console.WriteLine(Localized.MsgMessageFlagWithPassword);
                            return -1;
                        }

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
                        using (var ucrypter =  new Crypter(ks))
                        {
							if(_usecompression){

                                if (string.IsNullOrWhiteSpace(_compression)
                                    || _compression.Equals("zlib", StringComparison.InvariantCultureIgnoreCase))
                                {
                                    ucrypter.Compression = CompressionType.Zlib;
                                }
                                else if (_compression.Equals("gzip", StringComparison.InvariantCultureIgnoreCase))
                                {
                                    ucrypter.Compression = CompressionType.Gzip;
                                }
                                else
                                {
                                    Console.WriteLine("{0} {1}.", Localized.MsgUnknownCompression, _compression);
                                    return -1;
                                }
					
							}

                            ucrypter.Encrypt(inStream, outstream);
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
