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

using System;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Numerics;

namespace Keyczar.Crypto
{
    /// <summary>
    /// The Dsa Public Key
    /// </summary>
    public class DsaPublicKey : Key, IVerifierKey
    {
        /// <summary>
        /// Gets or sets the P.
        /// </summary>
        /// <value>The P.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger P { get; set; }

        /// <summary>
        /// Gets or sets the Q.
        /// </summary>
        /// <value>The Q.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger Q { get; set; }

        /// <summary>
        /// Gets or sets the G.
        /// </summary>
        /// <value>The G.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger G { get; set; }

        /// <summary>
        /// Gets or sets the Y.
        /// </summary>
        /// <value>The Y.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger Y { get; set; }


        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            var qMag = Utility.StripLeadingZeros(Utility.GetBytes(Q));
            var pMag = Utility.StripLeadingZeros(Utility.GetBytes(P));
            var gMag = Utility.StripLeadingZeros(Utility.GetBytes(G));
            var yMag = Utility.StripLeadingZeros(Utility.GetBytes(Y));
            var hash = Utility.HashKeyLengthPrefix(Keyczar.KeyHashLength, pMag, qMag, gMag, yMag);
            qMag.Clear();
            pMag.Clear();
            gMag.Clear();
            yMag.Clear();
            return hash;
        }

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
            Q = default(BigInteger);
            P = default(BigInteger);
            Y = default(BigInteger);
            G = default(BigInteger);
            Size = 0;
        }

        /// <summary>
        /// Gets the digest.
        /// </summary>
        /// <returns></returns>
        internal IDigest GetDigest()
        {
            var qSize = Q.ToBouncyBigInteger().BitLength;
            if (qSize <= 160)
                return new Sha1Digest(); //80 Bits of security
            if (qSize <= 224)
                return new Sha224Digest(); //112 Bits of security
            if (qSize <= 256)
                return new Sha256Digest(); //128 Bits of security

            //No keys should fall here or below with DSA2
            if (qSize <= 384)
                return new Sha384Digest(); //192 Bits of security
            return new Sha512Digest(); //256 Bits of security
        }

        /// <summary>
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetVerifyingStream()
        {
            var tSigner = new DsaSigner();
            tSigner.Init(forSigning: false, parameters: new DsaPublicKeyParameters(Y.ToBouncyBigInteger(),
                                                                                   new DsaParameters(
                                                                                       P.ToBouncyBigInteger(),
                                                                                       Q.ToBouncyBigInteger(),
                                                                                       G.ToBouncyBigInteger())));
            var digest = GetDigest();
            return new DigestStream(new DsaDigestSigner(tSigner, digest));
        }
    }
}