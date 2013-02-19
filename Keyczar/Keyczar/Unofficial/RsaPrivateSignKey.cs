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

using System.Numerics;
using Keyczar.Crypto;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Rsa Private Key For Signing with Update Hash Algorithms
    /// </summary>
    public class RsaPrivateSignKey : RsaPrivateSignKeyBase<RsaPublicSignKey>
    {
        /// <summary>
        /// Gets or sets the digest.
        /// </summary>
        /// <value>
        /// The digest.
        /// </value>
        [JsonIgnore]
        public string Digest
        {
            get { return PublicKey.Digest; }
            set { PublicKey.Digest = value; }
        }

        /// <summary>
        /// Generates the pub key.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="modulus">The modulus.</param>
        /// <returns></returns>
        protected override RsaPublicSignKey GeneratePubKey(int size, BigInteger publicExponent, BigInteger modulus)
        {
            return new RsaPublicSignKey
                       {
                           Size = size,
                           PublicExponent = publicExponent,
                           Modulus = modulus,
                           Digest = DigestForSize(size)
                       };
        }


        /// <summary>
        /// Picks the digests based on key size and relative strengths as described in NIST SP800-57.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <returns></returns>
        protected string DigestForSize(int size)
        {
            //Based on matching up digest strength equal or above key strength from
            //http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf

            if (size <= 1024)
                return RsaPublicSignKey.Sha1Digest; //80 Bits of security
            if (size <= 2048)
                return RsaPublicSignKey.Sha224Digest; //112 Bits of security
            if (size <= 3072)
                return RsaPublicSignKey.Sha256Digest; //128 Bits of security
            if (size <= 7680)
                return RsaPublicSignKey.Sha384Digest; //192 Bits of security
            return RsaPublicSignKey.Sha512Digest; //256 Bits of security
        }
    }
}