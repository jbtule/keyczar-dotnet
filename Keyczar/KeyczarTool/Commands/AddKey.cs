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
using Keyczar.Unofficial;
using ManyConsole.CommandLineUtils;

namespace KeyczarTool
{
    internal class AddKey : ConsoleCommand
    {
        private string _location;
        private KeyStatus _status;
        private int _size;
        private string _crypterLocation;
        private string _padding;
        private bool _password;
        private string _type;
        private bool _force;

        public AddKey()
        {
            this.IsCommand("addkey", Localized.AddKey);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });

            this.HasRequiredOption("s|status=", Localized.Status, v => { _status = v; });
            this.HasOption<int>("b|size=", Localized.Size, v => { _size = v; }); 
            this.HasOption("t|type:", Localized.KeyType, v => { _type = v; });
            this.HasOption("f|force", Localized.KeyType, v => { _force = true; });
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.HasOption("g|padding=", Localized.Padding, v => { _padding = v; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public static readonly IEnumerable<Tuple<KeyType, string>> KeyTypeMaps = new[]
        {
            Tuple.Create(KeyType.Aes, "AES_HMAC_SHA1"),
            Tuple.Create(KeyType.RsaPriv, "RSA_SHA1"),
            Tuple.Create(KeyType.DsaPriv, "DSA_SHA1"),
            Tuple.Create(KeyType.HmacSha1, "HMAC_SHA1"),
            Tuple.Create(UnofficialKeyType.AesAead, "AES_GCM"),
            Tuple.Create(UnofficialKeyType.RSAPrivSign, "RSA_PSS"),
            Tuple.Create(UnofficialKeyType.RSAPrivPkcs15Sign, "RSA_PKCS15"),
            Tuple.Create(UnofficialKeyType.HmacSha2, "HMAC_SHA2"),
            Tuple.Create(UnofficialKeyType.AesHmacSha2, "AES_HMAC_SHA2"),


        };



        public static  KeyType KeyTypeForString(string type)
        {
            if (String.IsNullOrWhiteSpace(type))
                return null;

            var found = KeyTypeMaps.FirstOrDefault(it =>
                String.Equals(it.Item2, type, StringComparison.InvariantCultureIgnoreCase));

            if (found != null) return found.Item1;
            
            switch (type.ToUpper())
            {
                case "RSA":
                    return KeyType.RsaPriv;
                case "DSA":
                    return KeyType.DsaPriv;
                default:
                    throw new ConsoleHelpAsException(string.Format(Localized.MsgInvalidType, type));
            }
        }
        
        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new FileSystemKeySet(_location);

            Func<string> crypterPrompt = CachedPrompt.Password(Util.PromptForPassword).Prompt;

            var prompt = ks.Metadata.Encrypted
                             ? new Func<string>(CachedPrompt.Password(Util.PromptForPassword).Prompt)
                             : new Func<string>(CachedPrompt.Password(Util.DoublePromptForPassword).Prompt);

            IDisposable dks = null;
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                if (_password)
                {
                    var cks = KeySet.LayerSecurity(
                                FileSystemKeySet.Creator(_crypterLocation),
                                PbeKeySet.Creator(crypterPrompt)
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

                if (_status != KeyStatus.Primary && _status != KeyStatus.Active)
                {
                    Console.WriteLine("{0} {1}.", Localized.MsgInvalidStatus, _status.Identifier);
                    return -1;
                }

                object options = null;
                if (!String.IsNullOrWhiteSpace(_padding))
                {
                    options = new {Padding = _padding};
                }

                int ver;
                var type = KeyTypeForString(_type);

                if (ks.Metadata.OriginallyOfficial && ks.Metadata.ValidOfficial())
                {
                    var keytype = ks.Metadata.OfficialKeyType();
                    if (type == null)
                    {
                        type = keytype;
                    } else if (type != keytype && !_force)
                    {
                        throw new ConsoleHelpAsException(String.Format(Localized.MsgMismatchedType, type, keytype));
                    }
                }


                try
                {
                    
                    ver = keySet.AddKey(_status, _size, type, options);
                }
#pragma warning disable 168
                catch (InvalidKeyTypeException ex)
#pragma warning restore 168
                {
                    throw new ConsoleHelpAsException(String.Format(Localized.MsgMismatchedKind, type?.Kind, keySet.Metadata.Kind));
                }


                IKeySetWriter writer = new FileSystemKeySetWriter(_location, overwrite: true);

                if (crypter != null)
                {
                    writer = new EncryptedKeySetWriter(writer, crypter);
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
                            Console.WriteLine("{0} {1}.", Localized.MsgCreatedKey, ver);
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
                Console.WriteLine("{0} {1}.", Localized.MsgCouldNotWrite, _location);
            }

            return ret;
        }
    }
}