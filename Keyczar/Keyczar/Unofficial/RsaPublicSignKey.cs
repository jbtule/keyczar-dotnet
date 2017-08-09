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
        public DigestAlg Digest { get; set; }


        internal override ISigner GetSigner()
        {
            IDigest digest;
            if (Digest == DigestAlg.Sha224)
            {
                digest = new Sha224Digest();
            }
            else if (Digest == DigestAlg.Sha256)
            {
                digest = new Sha256Digest();
            }
            else if (Digest == DigestAlg.Sha384)
            {
                digest = new Sha384Digest();
            }
            else if (Digest == DigestAlg.Sha512)
            {
                digest = new Sha512Digest();
            }
            else if (Digest == DigestAlg.Sha1)
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
                KeyczarConst.KeyHashLength,
                magModulus,
                magPublicExponent,
                Encoding.UTF8.GetBytes(Padding),
                Encoding.UTF8.GetBytes(Digest.ToString())
                );
            magModulus.Clear();
            magPublicExponent.Clear();
            return hash;
        }
    }
}