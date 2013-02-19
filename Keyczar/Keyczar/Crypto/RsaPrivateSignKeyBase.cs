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
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Keyczar.Crypto
{
    /// <summary>
    /// Base Class for RSA Implementations
    /// </summary>
    /// <typeparam name="TPublicKey">The type of the public key.</typeparam>
    public abstract class RsaPrivateSignKeyBase<TPublicKey> : Key, ISignerKey, IPrivateKey, IRsaPrivateKey
        where TPublicKey : RsaPublicSignKeyBase, IVerifierKey, IRsaPublicKey
    {
        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>
        /// The public key.
        /// </value>
        public TPublicKey PublicKey { get; set; }

        /// <summary>
        /// Gets or sets the private exponent.
        /// </summary>
        /// <value>The private exponent.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger PrivateExponent { get; set; }

        /// <summary>
        /// Gets or sets the prime P.
        /// </summary>
        /// <value>The prime P.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger PrimeP { get; set; }

        /// <summary>
        /// Gets or sets the prime Q.
        /// </summary>
        /// <value>The prime Q.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger PrimeQ { get; set; }

        /// <summary>
        /// Gets or sets the prime exponent P.
        /// </summary>
        /// <value>The prime exponent P.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger PrimeExponentP { get; set; }

        /// <summary>
        /// Gets or sets the prime exponent Q.
        /// </summary>
        /// <value>The prime exponent Q.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger PrimeExponentQ { get; set; }

        /// <summary>
        /// Gets or sets the CRT coefficient.
        /// </summary>
        /// <value>The CRT coefficient.</value>
        [JsonConverter(typeof (BigIntegerWebSafeBase64ByteConverter))]
        public BigInteger CrtCoefficient { get; set; }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        Key IPrivateKey.PublicKey
        {
            get { return PublicKey; }
        }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        IRsaPublicKey IRsaPrivateKey.PublicKey
        {
            get { return PublicKey; }
        }

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
            var rsaparam = new RsaKeyPairGenerator();
            rsaparam.Init(new KeyGenerationParameters(Secure.Random, size));
            var pair = rsaparam.GenerateKeyPair();
            var priv = (RsaPrivateCrtKeyParameters) pair.Private;
            PrivateExponent = priv.Exponent.ToSystemBigInteger();
            PrimeP = priv.P.ToSystemBigInteger();
            PrimeQ = priv.Q.ToSystemBigInteger();
            PrimeExponentP = priv.DP.ToSystemBigInteger();
            PrimeExponentQ = priv.DQ.ToSystemBigInteger();
            CrtCoefficient = priv.QInv.ToSystemBigInteger();

            var pub = (RsaKeyParameters) pair.Public;
            PublicKey = GeneratePubKey(size, pub.Exponent.ToSystemBigInteger(), pub.Modulus.ToSystemBigInteger());
        }

        /// <summary>
        /// Generates the pub key.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="modulus">The modulus.</param>
        /// <returns></returns>
        protected abstract TPublicKey GeneratePubKey(int size, BigInteger publicExponent, BigInteger modulus);


        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            PublicKey = PublicKey.SafeDispose();
            PrivateExponent = default(BigInteger);
            PrimeP = default(BigInteger);
            PrimeQ = default(BigInteger);
            PrimeExponentP = default(BigInteger);
            PrimeExponentQ = default(BigInteger);
            CrtCoefficient = default(BigInteger);
            Size = 0;
        }

        /// <summary>
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetVerifyingStream()
        {
            return PublicKey.GetVerifyingStream();
        }


        /// <summary>
        /// Gets the signing stream.
        /// </summary>
        /// <returns></returns>
        public HashingStream GetSigningStream()
        {
            var signer = PublicKey.GetSigner();

            signer.Init(forSigning: true, parameters: new RsaPrivateCrtKeyParameters(
                                              Utility.ToBouncyBigInteger(PublicKey.Modulus),
                                              Utility.ToBouncyBigInteger(PublicKey.PublicExponent),
                                              PrivateExponent.ToBouncyBigInteger(),
                                              PrimeP.ToBouncyBigInteger(),
                                              PrimeQ.ToBouncyBigInteger(),
                                              PrimeExponentP.ToBouncyBigInteger(),
                                              PrimeExponentQ.ToBouncyBigInteger(),
                                              CrtCoefficient.ToBouncyBigInteger()));

            return new DigestStream(signer, Size/8);
        }
    }
}