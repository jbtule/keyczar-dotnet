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
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using BouncyBigInteger =Org.BouncyCastle.Math.BigInteger;
using System.Numerics;

namespace Keyczar.Crypto
{
    /// <summary>
    /// The Dsa Public Key
    /// </summary>
    public class DsaPublicKey : Key,IVerifierkey
    {
        /// <summary>
        /// Gets or sets the P.
        /// </summary>
        /// <value>The P.</value>
        [JsonConverter(typeof(BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger P { get; set; }

        /// <summary>
        /// Gets or sets the Q.
        /// </summary>
        /// <value>The Q.</value>
		[JsonConverter(typeof(BigIntegerWebSafeBase64ByteConverter))]
		public BigInteger Q { get; set; }

        /// <summary>
        /// Gets or sets the G.
        /// </summary>
        /// <value>The G.</value>
		[JsonConverter(typeof(BigIntegerWebSafeBase64ByteConverter))]
		public BigInteger G { get; set; }

        /// <summary>
        /// Gets or sets the Y.
        /// </summary>
        /// <value>The Y.</value>
		[JsonConverter(typeof(BigIntegerWebSafeBase64ByteConverter))]
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
            var hash = Utility.HashKeyLengthPrefix(Keyczar.KEY_HASH_LENGTH, pMag, qMag, gMag, yMag);
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
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetVerifyingStream()
        {
            var tSigner = new DsaSigner();
            tSigner.Init(forSigning: false, parameters: new DsaPublicKeyParameters(Y.ToBouncyBigInteger(), 
                new DsaParameters(P.ToBouncyBigInteger(),Q.ToBouncyBigInteger(), G.ToBouncyBigInteger() ) ));
            return new DigestStream(new DsaDigestSigner(tSigner, new Sha1Digest()));
        }
    }
}