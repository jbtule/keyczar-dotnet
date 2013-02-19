/*  Copyright 2012 James Tuley (jay+code@tuley.name)
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

using System.Collections.Generic;
using System.IO;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using System.Numerics;
using Org.BouncyCastle.Crypto.Signers;
using BouncyBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Keyczar.Crypto
{
    /// <summary>
    /// The RSA Private Key
    /// </summary>
    public class RsaPrivateKey : RsaPrivateSignKeyBase<RsaPublicKey>, ICrypterKey
    {
        /// <summary>
        /// Gets or sets the padding.
        /// </summary>
        /// <value>The padding.</value>
        [JsonIgnore]
        public string Padding
        {
            get { return PublicKey.Padding; }
            set { PublicKey.Padding = value; }
        }

        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns>null</returns>
        public HashingStream GetAuthSigningStream()
        {
            return null; //not signed
        }

        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns>null</returns>
        public VerifyingStream GetAuthVerifyingStream()
        {
            return null; //not signed
        }

        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetEncryptingStream(Stream output)
        {
            return PublicKey.GetEncryptingStream(output);
        }

        /// <summary>
        /// Generates the pub key.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="modulus">The modulus.</param>
        /// <returns></returns>
        protected override RsaPublicKey GeneratePubKey(int size, BigInteger publicExponent, BigInteger modulus)
        {
            return new RsaPublicKey
                       {
                           Size = size,
                           PublicExponent = publicExponent,
                           Modulus = modulus
                       };
        }


        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetDecryptingStream(Stream output)
        {
            var rsa = new RsaEngine();
            var oaep = PublicKey.UpdatePadding(rsa);

            return new AsymmetricStream(oaep, output,
                                        (cipher, encrypt) => cipher.Init(encrypt, new RsaPrivateCrtKeyParameters(
                                                                                      PublicKey.Modulus
                                                                                               .ToBouncyBigInteger(),
                                                                                      PublicKey.PublicExponent
                                                                                               .ToBouncyBigInteger(),
                                                                                      PrivateExponent.ToBouncyBigInteger
                                                                                          (),
                                                                                      PrimeP.ToBouncyBigInteger(),
                                                                                      PrimeQ.ToBouncyBigInteger(),
                                                                                      PrimeExponentP.ToBouncyBigInteger(),
                                                                                      PrimeExponentQ.ToBouncyBigInteger(),
                                                                                      CrtCoefficient.ToBouncyBigInteger())),
                                        encrypt: false);
        }
    }
}