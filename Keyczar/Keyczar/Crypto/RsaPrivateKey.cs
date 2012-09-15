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

using System.Collections.Generic;
using System.IO;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Generators;

namespace Keyczar.Crypto
{
    /// <summary>
    /// The RSA Private Key
    /// </summary>
    public class RsaPrivateKey : Key, ICrypterKey, ISignerKey, IPrivateKey
    {
        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        public RsaPublicKey PublicKey { get; set; }

        /// <summary>
        /// Gets or sets the private exponent.
        /// </summary>
        /// <value>The private exponent.</value>
         [JsonConverter(typeof(WebSafeBase64ByteConverter))]
         public byte[] PrivateExponent { get; set; }
         /// <summary>
         /// Gets or sets the prime P.
         /// </summary>
         /// <value>The prime P.</value>
         [JsonConverter(typeof(WebSafeBase64ByteConverter))]
         public byte[] PrimeP { get; set; }
         /// <summary>
         /// Gets or sets the prime Q.
         /// </summary>
         /// <value>The prime Q.</value>
         [JsonConverter(typeof(WebSafeBase64ByteConverter))]
         public byte[] PrimeQ { get; set; }
         /// <summary>
         /// Gets or sets the prime exponent P.
         /// </summary>
         /// <value>The prime exponent P.</value>
         [JsonConverter(typeof(WebSafeBase64ByteConverter))]
         public byte[] PrimeExponentP { get; set; }
         /// <summary>
         /// Gets or sets the prime exponent Q.
         /// </summary>
         /// <value>The prime exponent Q.</value>
         [JsonConverter(typeof(WebSafeBase64ByteConverter))]
         public byte[] PrimeExponentQ { get; set; }
         /// <summary>
         /// Gets or sets the CRT coefficient.
         /// </summary>
         /// <value>The CRT coefficient.</value>
         [JsonConverter(typeof(WebSafeBase64ByteConverter))]
         public byte[] CrtCoefficient { get; set; }

        
         /// <summary>
         /// Gets the key hash.
         /// </summary>
         /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            return PublicKey.GetKeyHash();
        }
        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        Key IPrivateKey.PublicKey
        {
            get { return PublicKey; }
        }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size)
        {
            
            var rsaparam = new RsaKeyPairGenerator();
            rsaparam.Init(new KeyGenerationParameters(Random,size));
            var pair =rsaparam.GenerateKeyPair();
            var priv =(RsaPrivateCrtKeyParameters) pair.Private;
            PrivateExponent = priv.Exponent.ToByteArray();
            PrimeP = priv.P.ToByteArray();
            PrimeQ = priv.Q.ToByteArray();
            PrimeExponentP = priv.DP.ToByteArray();
            PrimeExponentQ = priv.DQ.ToByteArray();
            CrtCoefficient = priv.QInv.ToByteArray();

            var pub = (RsaKeyParameters) pair.Public;
            PublicKey = new RsaPublicKey
                            {
                                Size = size,
                                PublicExponent = pub.Exponent.ToByteArray(), 
                                Modulus = pub.Modulus.ToByteArray()};

        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public override void Dispose()
        {
            PublicKey = PublicKey.SafeDispose(); 
            PrivateExponent = PrivateExponent.Clear();
            PrimeP = PrimeP.Clear();
            PrimeQ = PrimeQ.Clear();
            PrimeExponentP = PrimeExponentP.Clear();
            PrimeExponentQ = PrimeExponentQ.Clear();
            CrtCoefficient = CrtCoefficient.Clear();
            Size = 0;
        }

        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns>null</returns>
        public HashingStream GetAuthSigningStream()
        {
            return null;  //not signed
        }
        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns>null</returns>
        public VerifyingStream GetAuthVerifyingStream()
        {
            return null; //not signed
        }

        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetEncryptingStream(Stream output)
        {
            return PublicKey.GetEncryptingStream(output);
        }

        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetDecryptingStream(Stream output)
        {
            var rsa = new RsaEngine();
            var oaep = PublicKey.UpdatePadding(rsa);

            return new AsymmetricStream(oaep, output, 
               (cipher, encrypt) => cipher.Init( encrypt, new RsaPrivateCrtKeyParameters(
                new BigInteger(PublicKey.Modulus),
                new BigInteger(PublicKey.PublicExponent),
                new BigInteger(PrivateExponent),
                new BigInteger(PrimeP),
                new BigInteger(PrimeQ),
                new BigInteger(PrimeExponentP),
                new BigInteger(PrimeExponentQ),
                new BigInteger(CrtCoefficient))),
                encrypt:false);
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
            var signer = new RsaDigestSigner(new Sha1Digest());
            
            signer.Init(forSigning: true, parameters: new RsaPrivateCrtKeyParameters(
                new BigInteger(PublicKey.Modulus),
                new BigInteger(PublicKey.PublicExponent),
                new BigInteger(PrivateExponent) ,
                new BigInteger(PrimeP), 
                new BigInteger(PrimeQ), 
                new BigInteger(PrimeExponentP),
                new BigInteger(PrimeExponentQ), 
                new BigInteger(CrtCoefficient)));

            return new DigestStream(signer);
        }

        /// <summary>
        /// Gets the length of the tag.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns>0</returns>
        public int GetTagLength(byte[] header)
        {
            return 0;
        }
    }
}