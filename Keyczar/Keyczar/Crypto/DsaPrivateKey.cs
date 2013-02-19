/*  Copyright 2012 James Tuley (jay+code@tuley.name)
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * 
 */

using System;
using System.Collections.Generic;
using System.IO;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using BouncyBigInteger = Org.BouncyCastle.Math.BigInteger;
using System.Numerics;

namespace Keyczar.Crypto
{
    /// <summary>
    /// The DSA private key
    /// </summary>
    public class DsaPrivateKey : Key, ISignerKey, IPrivateKey
    {
        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        public DsaPublicKey PublicKey { get; set; }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        Key IPrivateKey.PublicKey
        {
            get { return PublicKey; }
        }

        /// <summary>
        /// Gets or sets the X.
        /// </summary>
        /// <value>The X.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger X { get; set; }


        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            return PublicKey.GetKeyHash();
        }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size)
        {
            var paramgen = new DsaParametersGenerator();
            paramgen.Init(size, 100, Secure.Random);

            var keygen = new DsaKeyPairGenerator();
            keygen.Init(new DsaKeyGenerationParameters(Secure.Random, paramgen.GenerateParameters()));
            var pair = keygen.GenerateKeyPair();
            var priv = (DsaPrivateKeyParameters) pair.Private;
            X = priv.X.ToSystemBigInteger();
            Size = size;
            PublicKey = new DsaPublicKey();
            var pub = (DsaPublicKeyParameters) pair.Public;
            PublicKey.Y = pub.Y.ToSystemBigInteger();
            PublicKey.G = pub.Parameters.G.ToSystemBigInteger();
            PublicKey.P = pub.Parameters.P.ToSystemBigInteger();
            PublicKey.Q = pub.Parameters.Q.ToSystemBigInteger();
            PublicKey.Size = size;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            PublicKey = PublicKey.SafeDispose();
            X = default(BigInteger);
            Size = 0;
        }

        /// <summary>
        /// Gets the signing stream.
        /// </summary>
        /// <returns></returns>
        public HashingStream GetSigningStream()
        {
            var digest = PublicKey.GetDigest();
            var signer = new DsaDigestSigner(new DsaSigner(), digest);
            var param = new DsaPrivateKeyParameters(X.ToBouncyBigInteger(),
                                                    new DsaParameters(PublicKey.P.ToBouncyBigInteger(),
                                                                      PublicKey.Q.ToBouncyBigInteger(),
                                                                      PublicKey.G.ToBouncyBigInteger()));
            signer.Init(forSigning: true, parameters: new ParametersWithRandom(param, Secure.Random));

            return new DigestStream(signer);
        }

        /// <summary>
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetVerifyingStream()
        {
            return PublicKey.GetVerifyingStream();
        }
    }
}