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
        public ImportedKeySet(Key key, KeyPurpose purpose, string description = null)
        {
            _key = key;
            var keyType = key.KeyType;
            _metadata = new KeyMetadata()
            {
                Name = description ?? "Imported" + key.KeyType.Identifier,
                Purpose = purpose,
                Kind = key.KeyType.Kind,
                Versions = new List<KeyVersion>
                                  {
                                      new KeyVersion
                                      {
                                          KeyType = keyType,
                                          VersionNumber = 1,
                                          Status = KeyStatus.Primary,
                                          Exportable = false
                                      }
                                  }
            };
        }


        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {
            return Keyczar.RawStringEncoding.GetBytes(_key.ToJson());
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
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="ImportedKeySet" /> class.
        /// </summary>
        ~ImportedKeySet()
        {
            Dispose(false);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            _key = _key.SafeDispose();
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
                /// Initializes a new instance of the <see cref="PasswordFinder"/> class.
                /// </summary>
                /// <param name="password">The passsword.</param>
                public PasswordFinder(Func<string> password)
                {
                    _password = password;
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
                    return _password().ToCharArray();
                }
            }

            /// <summary>
            /// Import the PKCS key.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="path">The path.</param>
            /// <param name="passwordPrompt">The pass phrase prompt.</param>
            /// <returns></returns>
            public ImportedKeySet PkcsKey(KeyPurpose purpose, string path, Func<string> passwordPrompt = null)
            {
                using (var stream = File.OpenRead(path))
                    return PkcsKey(purpose, stream, passwordPrompt);
            }

            /// <summary>
            /// Import the PKCS key.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="input">The input.</param>
            /// <param name="passwordPrompt">The pass phrase prompt.</param>
            /// <returns></returns>
            /// <exception cref="InvalidKeySetException">DSA key cannot be used for encryption and decryption!</exception>
            /// <exception cref="InvalidKeySetException">Unsupported key type!</exception>
            public virtual ImportedKeySet PkcsKey(KeyPurpose purpose, Stream input, Func<string> passwordPrompt = null)
            {
                using (var password = CachedPrompt.Password(passwordPrompt))
                {
                    AsymmetricKeyParameter bouncyKey;
                    var resetStream = Utility.ResetStreamWhenFinished(input);
                    using (var streamReader = new NondestructiveStreamReader(input))
                    {
                        bouncyKey =
                            new PemReader(streamReader, new PasswordFinder(password.Prompt)).ReadObject() as
                            AsymmetricKeyParameter;
                    }

                    if (bouncyKey == null)
                    {
                        resetStream.Reset();
                        bouncyKey = passwordPrompt == null
                                        ? PrivateKeyFactory.CreateKey(input)
                                        : PrivateKeyFactory.DecryptKey(
                                            (password.Prompt() ?? String.Empty).ToCharArray(), input);
                    }

                    Key key;

                    if (bouncyKey is RsaPrivateCrtKeyParameters)
                    {
                        var keyParam = bouncyKey as RsaPrivateCrtKeyParameters;
                        key = new RsaPrivateKey()
                                  {
                                      PublicKey = new RsaPublicKey()
                                                      {
                                                          Modulus = keyParam.Modulus.ToSystemBigInteger(),
                                                          PublicExponent = keyParam.PublicExponent.ToSystemBigInteger(),
                                                          Size = keyParam.Modulus.BitLength,
                                                      },
                                      PrimeP = keyParam.P.ToSystemBigInteger(),
                                      PrimeExponentP = keyParam.DP.ToSystemBigInteger(),
                                      PrimeExponentQ = keyParam.DQ.ToSystemBigInteger(),
                                      PrimeQ = keyParam.Q.ToSystemBigInteger(),
                                      CrtCoefficient = keyParam.QInv.ToSystemBigInteger(),
                                      PrivateExponent = keyParam.Exponent.ToSystemBigInteger(),
                                      Size = keyParam.Modulus.BitLength,
                                  };
                    }
                    else if (bouncyKey is DsaPrivateKeyParameters)
                    {
                        var keyParam = bouncyKey as DsaPrivateKeyParameters;
                        if (KeyPurpose.DecryptAndEncrypt == purpose)
                        {
                            throw new InvalidKeySetException("DSA key cannot be used for encryption and decryption!");
                        }


                        key = new DsaPrivateKey()
                                  {
                                      X = keyParam.X.ToSystemBigInteger(),
                                      PublicKey = new DsaPublicKey
                                                      {
                                                          Y =
                                                              keyParam.Parameters.G.ModPow(keyParam.X,
                                                                                           keyParam.Parameters.P)
                                                                      .ToSystemBigInteger(),
                                                          G = keyParam.Parameters.G.ToSystemBigInteger(),
                                                          P = keyParam.Parameters.P.ToSystemBigInteger(),
                                                          Q = keyParam.Parameters.Q.ToSystemBigInteger(),
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
            }

            /// <summary>
            /// Imports the X509 the certificate.
            /// </summary>
            /// <param name="purpose">The purpose.</param>
            /// <param name="path">The path.</param>
            /// <returns></returns>
            /// <exception cref="InvalidKeySetException">DSA key cannot be used for encryption and decryption!</exception>
            /// <exception cref="InvalidKeySetException">Unsupported key type!</exception>
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
                                  Modulus = keyParam.Modulus.ToSystemBigInteger(),
                                  PublicExponent = keyParam.Exponent.ToSystemBigInteger(),
                                  Size = keyParam.Modulus.BitLength,
                              };
                }
                else if (bouncyKey is DsaPublicKeyParameters)
                {
                    var keyParam = bouncyKey as DsaPublicKeyParameters;
                    if (KeyPurpose.Encrypt == purpose)
                    {
                        throw new InvalidKeySetException("DSA key cannot be used for encryption!");
                    }
                    key = new DsaPublicKey
                              {
                                  Y = keyParam.Y.ToSystemBigInteger(),
                                  G = keyParam.Parameters.G.ToSystemBigInteger(),
                                  P = keyParam.Parameters.P.ToSystemBigInteger(),
                                  Q = keyParam.Parameters.Q.ToSystemBigInteger(),
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