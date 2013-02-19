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
using System.Linq;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Keyczar.Crypto
{
    /// <summary>
    /// The Hmac 256 Sha1 key
    /// </summary>
    public class HmacSha1Key : Key, ISignerKey, IVerifierKey
    {
        /// <summary>
        /// The hash size is 160 bits
        /// </summary>
        [JsonIgnore] public readonly int HashLength = 20;

        /// <summary>
        /// Gets or sets the hmac key bytes.
        /// </summary>
        /// <value>The hmac key bytes.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance",
            "CA1819:PropertiesShouldNotReturnArrays"), JsonConverter(typeof (WebSafeBase64ByteConverter))]
        [JsonProperty("HmacKeyString")]
        public byte[] HmacKeyBytes { get; set; }


        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            return Utility.HashKey(Keyczar.KeyHashLength, HmacKeyBytes);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            HmacKeyBytes = HmacKeyBytes.Clear();
        }

        /// <summary>
        /// Gets the signing stream.
        /// </summary>
        /// <returns></returns>
        public HashingStream GetSigningStream()
        {
            return GetVerifyingStream();
        }

        /// <summary>
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetVerifyingStream()
        {
            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new KeyParameter(HmacKeyBytes));
            return new HmacStream(hmac);
        }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size)
        {
            HmacKeyBytes = new byte[size/8];
            Secure.Random.NextBytes(HmacKeyBytes);
        }
    }
}