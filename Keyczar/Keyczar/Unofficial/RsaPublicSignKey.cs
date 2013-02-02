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

using System.Text;
using Keyczar.Crypto;
using Keyczar.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;

namespace Keyczar.Unofficial
{  
    
    /// <summary>
    /// Rsa Public Key For Signing with Update Hash Algorithms
    /// </summary>
    public class RsaPublicSignKey:RsaPublicSignKeyBase
    {
        public static readonly string Sha1Digest = "SHA1";

        public static readonly string Sha224Digest = "SHA224";

        public static readonly string Sha256Digest = "SHA256";

        public static readonly string Sha384Digest = "SHA384";

        public static readonly string Sha512Digest = "SHA512";

  

        /// <summary>
        /// Gets or sets the digest.
        /// </summary>
        /// <value>
        /// The digest.
        /// </value>
        public string Digest { get; set; }

        internal override ISigner GetSigner()
        {
            IDigest digest;
            if (Digest == Sha224Digest)
            {
                digest = new Sha224Digest();
            }
            else if (Digest == Sha256Digest)
            {
                digest = new Sha256Digest();
            }
            else if (Digest == Sha384Digest)
            {
                digest = new Sha384Digest();
            }
            else if (Digest == Sha512Digest)
            {
                 digest = new Sha512Digest();
            }
            else if (Digest == Sha1Digest)
            {
                digest = new Sha1Digest();
            }
            else
            {
                throw new InvalidKeyTypeException(string.Format("Unknown digest type :{0}", Digest));
            }

            return new PssSigner(new RsaBlindedEngine(), digest);
        }

        public override byte[] GetKeyHash()
        {
            var magModulus = Utility.StripLeadingZeros(Utility.GetBytes(Modulus));
            var magPublicExponent = Utility.StripLeadingZeros(Utility.GetBytes(PublicExponent));

            var hash = Utility.HashKeyLengthPrefix(
                Keyczar.KeyHashLength,
                magModulus,
                magPublicExponent,
                Encoding.UTF8.GetBytes(Digest));
            magModulus.Clear();
            magPublicExponent.Clear();
            return hash;
        }
    }
}
