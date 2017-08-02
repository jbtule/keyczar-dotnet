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
using System;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Rsa Public Key For Signing with Update Hash Algorithms
    /// </summary>
    public class RsaPublicSignKey : RsaPublicSignKeyBase
    {
        /// <summary>
        /// The sha1 digest
        /// </summary>
        public static readonly string Sha1Digest = "SHA1";

        /// <summary>
        /// The sha224 digest
        /// </summary>
        public static readonly string Sha224Digest = "SHA224";

        /// <summary>
        /// The sha256 digest
        /// </summary>
        public static readonly string Sha256Digest = "SHA256";

        /// <summary>
        /// The sha384 digest
        /// </summary>
        public static readonly string Sha384Digest = "SHA384";

        /// <summary>
        /// The sha512 digest
        /// </summary>
        public static readonly string Sha512Digest = "SHA512";


        /// <summary>
        /// Pss Padding identifer
        /// </summary>
        public static readonly string PssPadding = "PSS";

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaPublicSignKey" /> class.
        /// </summary>
        public RsaPublicSignKey()
        {
            Padding = PssPadding;
        }

        /// <summary>
        /// Gets or sets the Padding (Only PSS is supported).
        /// </summary>
        /// <value>The Padding.</value>
        public string Padding { get; set; }

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
            if (Padding == PssPadding)
            {
                return new PssSigner(new RsaBlindedEngine(), digest);
            }
            throw new InvalidKeyTypeException(string.Format("Unknown padding type :{0}", Padding));
        }

        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            var magModulus = Utility.StripLeadingZeros(Utility.GetBytes(Modulus));
            var magPublicExponent = Utility.StripLeadingZeros(Utility.GetBytes(PublicExponent));

            var hash = Utility.HashKeyLengthPrefix(
                Keyczar.KeyHashLength,
                magModulus,
                magPublicExponent,
                Encoding.UTF8.GetBytes(Padding),
                Encoding.UTF8.GetBytes(Digest)
                );
            magModulus.Clear();
            magPublicExponent.Clear();
            return hash;
        }
    }
}