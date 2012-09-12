/* Copyright 2012 James Tuley (jay+code@tuley.name)
*  
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*  
*      http://www.apache.org/licenses/LICENSE-2.0
*  
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;
namespace Keyczar.Compat
{
    /// <summary>
    /// Imported Keyset, can be used for compatiblity with keys stored as PEM,DER or X509 certificates
    /// </summary>
    public class ImportedKeySet : IKeySet, IDisposable
    {
        /// <summary>
        /// Methods of this property are the import commands
        /// </summary>
        public static Importer Import = new Importer();

   

        private readonly KeyMetadata _metadata;
        private Key _key;

        /// <summary>
        /// Initializes a new instance of the <see cref="ImportedKeySet"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="purpose">The purpose.</param>
        /// <param name="description">The description.</param>
        public ImportedKeySet(Key key, KeyPurpose purpose, string description =null)
        {
            _key = key;
            var keyType = key.Type;
            _metadata = new KeyMetadata()
            {
                Name = description ?? "Imported" + key.Type.Identifier,
                Purpose = purpose,
                Type = keyType,
                Versions = new List<KeyVersion>
                                  {
                                      new KeyVersion
                                      {
                                          VersionNumber = 0,
                                          Status = KeyStatus.PRIMARY,
                                          Exportable = false
                                      }
                                  }
            };
        }

        /// <summary>
        /// Gets the key.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public Key GetKey(int version)
        {
            return _key;
        }

        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {
            return Keyczar.DefaultEncoding.GetBytes(JsonConvert.SerializeObject(_key));
        }

        /// <summary>
        /// Gets the meta data.
        /// </summary>
        /// <value>The meta data.</value>
        public KeyMetadata Metadata
        {
            get { return _metadata; }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _key.Dispose();
            _key = null;
        }

        /// <summary>
        /// Turns files into importedkeysets
        /// </summary>
        public class Importer
        {
            /// <summary>
            ///  password finder used for bouncy castle api
            /// </summary>
            public class PasswordFinder : IPasswordFinder
            {
                private Func<string> _password;

                /// <summary>
                /// Initializes a new instance of the <see cref="DummyPasswordFinder"/> class.
                /// </summary>
                /// <param name="passsword">The passsword.</param>
                public PasswordFinder(Func<string> passsword)
                {
                    _password = passsword;
                }

                /// <summary>
                /// Gets the password.
                /// </summary>
                /// <returns></returns>
                public char[] GetPassword()
                {
                    if (_password == null)
                    {
                        return null;
                    }
                    return  _password().ToCharArray();
                }
            }

            /// <summary>
            /// Import the PKCS key.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="path">The path.</param>
            /// <param name="passPhrasePrompt">The pass phrase prompt.</param>
            /// <returns></returns>
            public ImportedKeySet PkcsKey(KeyPurpose purpose, string path, Func<string> passPhrasePrompt = null)
            {
                using (var stream = File.OpenRead(path))
                    return PkcsKey(purpose, stream, passPhrasePrompt);
            }

            /// <summary>
            /// Import the PKCS key.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="input">The input.</param>
            /// <param name="passPhrasePrompt">The pass phrase prompt.</param>
            /// <returns></returns>
            public virtual ImportedKeySet PkcsKey(KeyPurpose purpose, Stream input, Func<string> passPhrasePrompt = null)
            {
                AsymmetricKeyParameter bouncyKey = null;
                var position = input.Position;
                string _passPhrase =null;
                bool _passPhraseRun = false;
                Func<string> cachedPrompt =
                () =>
                     {
                         if (!_passPhraseRun && passPhrasePrompt != null)
                         {
                             _passPhrase = passPhrasePrompt();
                             _passPhraseRun = true;
                         }
                         return _passPhrase;
                     };
                using (var streamReader = new NonDestructiveStreamReader(input))
                {
                    bouncyKey = new PemReader(streamReader, new PasswordFinder(cachedPrompt)).ReadObject() as AsymmetricKeyParameter;
                }

                if(bouncyKey == null)
                {
                    input.Seek(position, SeekOrigin.Begin);
                    bouncyKey = passPhrasePrompt ==null
                                    ? PrivateKeyFactory.CreateKey(input)
                                    : PrivateKeyFactory.DecryptKey((passPhrasePrompt()?? String.Empty).ToCharArray(), input);
                }

                Key key;

                if (bouncyKey is RsaPrivateCrtKeyParameters)
                {
                    var keyParam = bouncyKey as RsaPrivateCrtKeyParameters;
                    key = new RsaPrivateKey()
                    {
                        PublicKey = new RsaPublicKey()
                        {
                            Modulus = keyParam.Modulus.ToByteArray(),
                            PublicExponent = keyParam.PublicExponent.ToByteArray(),
                            Size = keyParam.Modulus.BitLength,
                        },
                        PrimeP = keyParam.P.ToByteArray(),
                        PrimeExponentP = keyParam.DP.ToByteArray(),
                        PrimeExponentQ = keyParam.DQ.ToByteArray(),
                        PrimeQ = keyParam.Q.ToByteArray(),
                        CrtCoefficient = keyParam.QInv.ToByteArray(),
                        PrivateExponent = keyParam.Exponent.ToByteArray(),
                        Size = keyParam.Modulus.BitLength,
                    };

                }
                else if (bouncyKey is DsaPrivateKeyParameters)
                {
                    var keyParam = bouncyKey as DsaPrivateKeyParameters;
                    if (KeyPurpose.DECRYPT_AND_ENCRYPT == purpose)
                    {
                        throw new InvalidKeySetException("DSA key cannot be used for encryption and decryption!");
                    }


                    key = new DsaPrivateKey()
                    {
                        X = keyParam.X.ToByteArray(),
                        PublicKey = new DsaPublicKey
                        {
                            Y =
                                keyParam.Parameters.G.ModPow(keyParam.X, keyParam.Parameters.P)
                                .ToByteArray(),
                            G = keyParam.Parameters.G.ToByteArray(),
                            P = keyParam.Parameters.P.ToByteArray(),
                            Q = keyParam.Parameters.Q.ToByteArray(),
                            Size = keyParam.Parameters.P.BitLength
                        },
                        Size = keyParam.Parameters.P.BitLength
                    };
                }
                else
                {
                    throw new InvalidKeySetException("Unsupported key type!");
                }


                return new ImportedKeySet(key, purpose, "imported from pkcs file");
            }

            /// <summary>
            /// Imports the X509 the certificate.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="path">The path.</param>
            /// <returns></returns>
            public ImportedKeySet X509Certificate(KeyPurpose purpose, string path)
            {
                using (var stream = File.OpenRead(path))
                    return X509Certificate(purpose, stream);
            }

            /// <summary>
            /// Imports the X509 certificate.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="input">The input.</param>
            /// <returns></returns>
            public virtual ImportedKeySet X509Certificate(KeyPurpose purpose, Stream input)
            {

                var parser = new X509CertificateParser();
                var cert = parser.ReadCertificate(input);
                var bouncyKey = cert.GetPublicKey();

                Key key;
                if (bouncyKey is RsaKeyParameters)
                {
                    var keyParam = bouncyKey as RsaKeyParameters;
                    key = new RsaPublicKey
                    {
                        Modulus = keyParam.Modulus.ToByteArray(),
                        PublicExponent = keyParam.Exponent.ToByteArray(),
                        Size = keyParam.Modulus.BitLength,
                    };
                }
                else if (bouncyKey is DsaPublicKeyParameters)
                {
                    var keyParam = bouncyKey as DsaPublicKeyParameters;
                    if (KeyPurpose.ENCRYPT == purpose)
                    {
                        throw new InvalidKeySetException("DSA key cannot be used for encryption!");
                    }
                    key = new DsaPublicKey
                    {
                        Y = keyParam.Y.ToByteArray(),
                        G = keyParam.Parameters.G.ToByteArray(),
                        P = keyParam.Parameters.P.ToByteArray(),
                        Q = keyParam.Parameters.Q.ToByteArray(),
                        Size = keyParam.Parameters.P.BitLength
                    };
                }
                else
                {
                    throw new InvalidKeySetException("Unsupported key type!");
                }
                return new ImportedKeySet(key, purpose, "imported from certificate");

            }
        }
    }
}
