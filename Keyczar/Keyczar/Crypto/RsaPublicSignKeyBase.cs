/*  Copyright 2013 James Tuley (jay+code@tuley.name)
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
using System.Numerics;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Keyczar.Crypto
{
    /// <summary>
    /// Base class for Rsa Key Implementations
    /// </summary>
    public abstract class RsaPublicSignKeyBase : Key, IVerifierKey, IRsaPublicKey
    {
        /// <summary>
        /// Gets or sets the modulus.
        /// </summary>
        /// <value>The modulus.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger Modulus { get; set; }

        /// <summary>
        /// Gets or sets the public exponent.
        /// </summary>
        /// <value>The public exponent.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger PublicExponent { get; set; }


        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <exception cref="System.NotSupportedException"></exception>
        protected override void GenerateKey(int size)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            Modulus = default(BigInteger);
            PublicExponent = default(BigInteger);
            Size = 0;
        }


        internal abstract ISigner GetSigner();

        /// <summary>
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetVerifyingStream()
        {
            var signer = GetSigner();
            signer.Init(forSigning: false, parameters: new RsaKeyParameters(false,
                                                                            Modulus.ToBouncyBigInteger(),
                                                                            PublicExponent.ToBouncyBigInteger()));
            return new DigestStream(signer, Size/8);
        }
    }
}