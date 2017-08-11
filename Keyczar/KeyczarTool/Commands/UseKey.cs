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
using Keyczar.Unofficial;
using ManyConsole;
using Keyczar.Util;
using Newtonsoft.Json.Linq;

namespace KeyczarTool
{
    public class UseKey : ConsoleCommand
    {
        private string _location;
        private string _location2;
        private string _crypterLocation;
        private string _crypterLocation2;
        private WireFormat _format;
        private string _message;
        private bool _file;
        private string _destination;
        private string _destination2;
        private bool _binary;
        private bool _password;
        private bool _password2;
		private bool _usecompression;
		string _compression;
        private DateTime? _expires;
        private string _attachedHidden;



        public UseKey()
        {
            this.IsCommand("usekey", Localized.UseKey);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasOption("location2=", Localized.Location2, v => { _location2 = v; });
            this.HasOption("format=", Localized.Format, v => { _format = v; });
            this.HasOption("d|destination=", Localized.Destination, v => { _destination = v; });
            this.HasOption("destination2=", Localized.Destination2, v => { _destination2 = v; });
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("crypter2=", Localized.Crypter2, v => { _crypterLocation2 = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.HasOption("password2", Localized.Password2, v => { _password2 = true; });
            this.HasOption("file", Localized.File, v => { _file = true; });
            this.HasOption("binary", Localized.Binary, v => { _binary = true; });
			this.HasOption("compression:", Localized.Compression, v => {_usecompression = true; _compression = v; });
            this.AllowsAnyAdditionalArguments("message [extra-parameters...]");
            this.SkipsCommandSummaryBeforeRunning();
        }  

     

        public override int Run(string[] remainingArguments)
        {

            if (remainingArguments.Length > 0)
            {
                _message = remainingArguments[0];

                if (_format == WireFormat.SignTimeout)
                {  
                    DateTime outDate;
                    if (remainingArguments.Length > 1 && DateTime.TryParse(remainingArguments[1], out outDate))
                    {
                        _expires = outDate;
                    }
                    else
                    {
                        throw new ConsoleHelpAsException("Missing or wrong format extra-parameter (expiration-datetime, ISO 8601 for sign-timeout)");
                    }
                }else if (_format == WireFormat.SignAttached)
                {
                    if (remainingArguments.Length > 1)
                    {
                        _attachedHidden = remainingArguments[1];
                    }
                }
            }

            IDisposable d1 = null;
            IDisposable d2 = null;
            IDisposable d3 = null;
            IDisposable d4 = null;
            IDisposable d5 = null;
            IDisposable d6 = null;

            var config = KeyczarDefaults.DefaultConfig;

            IKeySet ks = ProduceKeySet(_location, _crypterLocation, _password, out d1, out d2, out d3);
            IKeySet ks2 = ProduceKeySet(_location2, _crypterLocation2, _password2, out d4, out d5, out d6);

            using (d1)
            using (d2)
            using (d3)
            using (d4)
            using (d5)
            using (d6)
            {

                    Stream inStream;
                    if (String.IsNullOrWhiteSpace(_message))
                    {
                        if (_password)
                        {
                            Console.WriteLine(Localized.MsgMessageFlagWithPassword);
                            return -1;
                        }

                         if (_format == WireFormat.CryptSession || _format == WireFormat.CryptSignedSession)
                        {
                            Console.WriteLine(Localized.MsgMessageFlagSession);
                            return -1;
                        }

                        inStream = Console.OpenStandardInput();
                    }else if (_file)
                    {
                        inStream = File.OpenRead(_message);
                    }else
                    {
                        inStream = new MemoryStream(config.RawStringEncoding.GetBytes(_message));
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

                Stream outstream2 = null;
                if ((_format == WireFormat.CryptSession || _format == WireFormat.CryptSignedSession) &&
                    String.IsNullOrWhiteSpace(_destination2))
                {
                    Console.WriteLine(Localized.MsgRequiresDestination2);
                    return -1;
                }
                else if (_binary & !String.IsNullOrWhiteSpace(_destination2))
                {
                    outstream2 = File.Open(_destination2, FileMode.CreateNew);
                }
                else
                {
                    outstream2 = new MemoryStream();
                }


                using(inStream)
                using(outstream)
                using(outstream2)
                {
                    var err = TakeAction(ks, inStream, outstream, outstream2, ks2 );
                    if (err != 0)
                        return err;
                    if (!_binary)
                    {
                        EncodeData(outstream, _destination);
                        EncodeData(outstream2, _destination2);
                    }
                }
            }

            return 0;
        }

        private void EncodeData(Stream outstream, string destination)
        {
            var memstream = (MemoryStream) outstream;
            outstream.Flush();
            var encodedOutput = _format != WireFormat.SignJwt
                ? WebBase64.FromBytes(memstream.ToArray()).ToString()
                : Encoding.UTF8.GetString(memstream.ToArray());

            if (String.IsNullOrWhiteSpace(destination))
            {
                Console.Write(encodedOutput);
            }
            else
            {
                if (File.Exists(destination))
                    throw new Exception("File already Exists!!");
           
                File.WriteAllText(destination, encodedOutput);
            }
        }

        protected IKeySet ProduceKeySet(string location, string crypterLocation, bool password, out IDisposable d1, out IDisposable d2, out IDisposable d3)
        {
            if (String.IsNullOrWhiteSpace(location))
            {
                d1 = null;
                d2 = null;
                d3 = null;
               return null;
            }
           
            Crypter crypter = null;
            IKeySet ks = new FileSystemKeySet(location);
            Func<string> prompt = CachedPrompt.Password(Util.PromptForPassword).Prompt;

            IDisposable dks =null;
            if (!String.IsNullOrWhiteSpace(crypterLocation))
            {
                if (password)
                {
                    var cks = KeySet.LayerSecurity(FileSystemKeySet.Creator(crypterLocation),
                                                   PbeKeySet.Creator(prompt)
                                                  );
                    crypter = new Crypter(cks);
                    dks = cks;
                }
                else
                {
                    crypter = new Crypter(crypterLocation);
                }
                ks = new EncryptedKeySet(ks, crypter);
            }
            else if (_password)
            {
                ks = new PbeKeySet(ks, prompt);
            }
       
            d1 = crypter;
            d2 = dks;
            d3 = ks;
            return ks;
        }
        
        protected int UseCompression(dynamic compression)
        {
          
                    if (_usecompression)
                    {
                        if (string.IsNullOrWhiteSpace(_compression)
                            || _compression.Equals("zlib", StringComparison.InvariantCultureIgnoreCase))
                        {
                            compression.Compression = CompressionType.Zlib;
                        }
                        else if (_compression.Equals("gzip", StringComparison.InvariantCultureIgnoreCase))
                        {
                            compression.Compression = CompressionType.Gzip;
                        }
                        else
                        {
                            Console.WriteLine("{0} {1}.", Localized.MsgUnknownCompression, _compression);
                            return -1;
                        }
                    }
            return 0;
        }

        protected int TakeAction(IKeySet keyset, Stream inStream, Stream outStream, Stream outStream2, IKeySet keyset2)
        {
            if ((WireFormat.IsNullOrEmpty(_format)
                        && (keyset.Metadata.Purpose == KeyPurpose.DecryptAndEncrypt
                                || keyset.Metadata.Purpose == KeyPurpose.Encrypt))
                || _format == WireFormat.Crypt 
                )
            {
                using (var ucrypter = new Encrypter(keyset))
                {
                    
                    var err =UseCompression(ucrypter);
                    if (err != 0)
                        return err;
                    ucrypter.Encrypt(inStream, outStream);
                }
            }
            else if (WireFormat.IsNullOrEmpty(_format) || _format == WireFormat.Sign)
            {
                using (var signer = new Signer(keyset))
                    {
                        var sig = signer.Sign(inStream);
                        outStream.Write(sig, 0, sig.Length);
                    }
            }  
            else if (_format == WireFormat.SignJwt)
            {
                try
                {
                    using (var signer = new JwtSigner(keyset))
                    using (var reader =new StreamReader(inStream))
                    {
                        
                            var sig = signer.SignCompact(JObject.Parse(reader.ReadToEnd()));
                            outStream.Write(Encoding.UTF8.GetBytes(sig), 0, sig.Length);
                      
                    }
                    
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine(ex.StackTrace);
                    return -1;
                }
            }
            else if (_format == WireFormat.SignTimeout)
            {
                using (var signer = new TimeoutSigner(keyset))
                {
                    var sig = signer.Sign(inStream,_expires.GetValueOrDefault());
                    outStream.Write(sig, 0, sig.Length);
                }
            }
            else if (_format == WireFormat.SignAttached)
            {
                using (var signer = new AttachedSigner(keyset))
                {
                    byte[] hidden = null;
                    if (!String.IsNullOrWhiteSpace(_attachedHidden))
                        hidden = signer.Config.RawStringEncoding.GetBytes(_attachedHidden);
                    signer.Sign(inStream, outStream, hidden);
                }
            }
            else if (_format == WireFormat.SignVanilla || _format == WireFormat.SignUnversioned)
            {
                using (var signer = new Keyczar.Compat.VanillaSigner(keyset))
                {
                    var sig = signer.Sign(inStream);
                    outStream.Write(sig, 0, sig.Length);
                }
            } 
            else if (_format == WireFormat.CryptSession)
            {
                using (var crypter = new Encrypter(keyset))
                using (var sessionCrypter = new SessionCrypter(crypter))
                {
                    var err = UseCompression(sessionCrypter);
                    if (err != 0)
                        return err;
                    var materials = sessionCrypter.SessionMaterial.ToBytes();
                    outStream.Write(materials, 0, materials.Length);

                    sessionCrypter.Encrypt(inStream, outStream2);
                }
            }
            else if (_format == WireFormat.CryptSignedSession)
            {
                if (keyset2 == null)
                {
                    Console.WriteLine(Localized.MsgRequiresLocation2);
                    return -1;
                }

                using (var crypter = new Encrypter(keyset))
                using (var signer = new AttachedSigner(keyset2))
                using (var sessionCrypter = new SessionCrypter(crypter, signer))
                {
                    var err = UseCompression(sessionCrypter);
                    if (err != 0)
                        return err;
                    var materials = sessionCrypter.SessionMaterial.ToBytes();
                    outStream.Write(materials, 0, materials.Length);

                    sessionCrypter.Encrypt(inStream, outStream2);
                }
            }
            else
            {
                Console.WriteLine(Localized.MsgUnknownFormat,_format);
                return -1;
            }
            return 0;
        }

        


        protected class WireFormat : Keyczar.Util.StringType
        {

            public static readonly WireFormat Crypt = "CRYPT";
            public static readonly WireFormat Sign = "SIGN";
            public static readonly WireFormat SignTimeout = "SIGN-TIMEOUT";
            public static readonly WireFormat SignVanilla = "SIGN-VANILLA";
            public static readonly WireFormat SignUnversioned = "SIGN-UNVERSIONED"; 
            public static readonly WireFormat SignAttached = "SIGN-ATTACHED";
            public static readonly WireFormat SignJwt = "SIGN-JWT";
            public static readonly WireFormat CryptSession = "CRYPT-SESSION";
            public static readonly WireFormat CryptSignedSession = "CRYPT-SIGNEDSESSION";

            public static implicit operator WireFormat(string identifier)
            {
                return new WireFormat(identifier);
            }

            public WireFormat(string identifier)
                : base(identifier)
            {
            }
        }
    }
}
