/* 
 * Copyright 2012 James Tuley (jay+code@tuley.name)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Paddings;
namespace Keyczar.Crypto
{
   
 
    /// <summary>
    /// Encrypts AES
    /// </summary>
    public class AesKey : Key, ICrypterKey
    {
        /// <summary>
        /// Block size is 128bits
        /// </summary>
        [JsonIgnore]
        public readonly int BlockLength = 16;

        /// <summary>
        /// Gets or sets the mode only CBC supported.
        /// </summary>
        /// <value>The block cipher mode.</value>
        public string Mode { get; set; }

        /// <summary>
        /// Gets or sets the aes key bytes.
        /// </summary>
        /// <value>The aes key bytes.</value>
        [JsonConverter(typeof(WebSafeBase64ByteConverter))]
        [JsonProperty("AesKeyString")]
        public byte[] AesKeyBytes { get; set; }

        /// <summary>
        /// Gets or sets the hmac key.
        /// </summary>
        /// <value>The hmac key.</value>
        public HmacSha1Key HmacKey { get; set; }

        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            return Utility.HashKey(Keyczar.KEY_HASH_LENGTH, Utility.GetBytes(AesKeyBytes.Length), AesKeyBytes,
                                  HmacKey.HmacKeyBytes);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesKey"/> class.
        /// </summary>
        public AesKey()
        {
            Mode = "CBC";//Default Mode
        }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size)
        {
            AesKeyBytes= new byte[size/8];
            Random.NextBytes(AesKeyBytes);
            HmacKey = (HmacSha1Key) Generate(KeyType.HMAC_SHA1, 0/*uses default size*/);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public override void Dispose()
        {
            Mode = null;
            AesKeyBytes = AesKeyBytes.Clear();
            HmacKey = HmacKey.SafeDispose();
        }


        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns></returns>
        public HashingStream GetAuthSigningStream()
        {
            return HmacKey.Maybe(h=>h.GetSigningStream(),()=> null);
        }
        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetAuthVerifyingStream()
        {
			return HmacKey.Maybe(h=>h.GetVerifyingStream(),()=> null);
        }

        /// <summary>
        /// Gets the mode.
        /// </summary>
        /// <returns></returns>
        private CipherMode GetMode()
        {
            if (Mode == "CBC")
            {
                return CipherMode.CBC;
            }
            throw new InvalidKeyTypeException("Unsupport AES Mode: " + Mode);
        }

        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetEncryptingStream(Stream output)
        {
            var alg = new AesManaged
                          {
                              Mode = GetMode(),
                              Key = AesKeyBytes,
                              Padding = PaddingMode.PKCS7,
                              BlockSize = BlockLength * 8
                          };
            alg.GenerateIV();
		

			int hashlength =HmacKey.Maybe(h=>h.HashLength,()=>0);
			return new DotNetSymmetricStream(alg, output,hashlength , encrypt: true);


            //Bouncy Castle Version-->
            // var ivarr = new byte[BlockLength];
            //Random.NextBytes(ivarr);
            // return new SymmetricStream(
            // new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
            // output,
            // ivarr,
            // HmacKey.HashLength,
            // (iv, cipher, encrypt) => cipher.Init(forEncryption: encrypt, parameters: new ParametersWithIV(new KeyParameter(AesKeyBytes), iv)),
            // encrypt: true);

        }

        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetDecryptingStream(Stream output)
        {
            var alg = new AesManaged
                          {
                              Mode = GetMode(),
                              Key = AesKeyBytes,
                              Padding = PaddingMode.PKCS7,
                              BlockSize = BlockLength * 8
                          };
            return new DotNetSymmetricStream(alg, output, HmacKey.Maybe(h=>h.HashLength,()=>0), encrypt: false);

               //Bouncy Castle Version-->
               //return new SymmetricStream(
               //     new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
               //     output, 
               //     new byte[BlockLength],
               //     HmacKey.HashLength,
               //     (iv, cipher, encrypt) => cipher.Init(forEncryption: encrypt, parameters: new ParametersWithIV(new KeyParameter(AesKeyBytes), iv)),
               //     encrypt:false);
        }

    }
}