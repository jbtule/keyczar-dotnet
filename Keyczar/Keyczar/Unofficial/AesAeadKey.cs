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
using System.Text;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Uses Authenticated Encryption with Associated Data Mode with AES.
    /// Specficially supports GCM mode.
    /// </summary>
    public class AesAeadKey:Key,ICrypterKey
    {
        private static readonly SecureRandom RANDOM = new SecureRandom();

        /// <summary>
        /// Uses 128bit block size
        /// </summary>
        [JsonIgnore]
        public readonly int BlockLength = 16;

        /// <summary>
        /// Uses 128bit MAC
        /// </summary>
        [JsonIgnore]
        public readonly int TagLength = 16;

        /// <summary>
        /// Uses an 128bit random nonce
        /// </summary>
        [JsonIgnore]
        public readonly int NonceLength = 16;

        /// <summary>
        /// Gets or sets the mode (Only GCM is supported).
        /// </summary>
        /// <value>The mode.</value>
        public string Mode { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesAeadKey"/> class.
        /// </summary>
        public AesAeadKey()
        {
            Mode = "GCM";//Default Mode
        }

        /// <summary>
        /// Gets or sets the aes key bytes.
        /// </summary>
        /// <value>The aes key bytes.</value>
        [JsonConverter(typeof(WebSafeBase64ByteConverter))]
        [JsonProperty("AesKeyString")]
        public byte[] AesKeyBytes { get; set; }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size)
        {
            AesKeyBytes = new byte[size / 8];
            Random.NextBytes(AesKeyBytes);
        }

        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            return Utility.HashKey(Keyczar.KEY_HASH_LENGTH, Utility.GetBytes(BlockLength), Encoding.UTF8.GetBytes(Mode), AesKeyBytes);
        }

        private Func<IBlockCipher, IAeadBlockCipher> GetMode()
        {
            if (Mode == "GCM")
            {
                return cipher => new GcmBlockCipher(cipher);

            }
            throw new InvalidKeyTypeException("Unsupported AES AEAD Mode: " + Mode);
        }

        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetEncryptingStream(Stream output)
        {


            var randomNonce = new byte[NonceLength];
            RANDOM.NextBytes(randomNonce, 0, randomNonce.Length);
            return new AesAeadStream(
                         GetMode(),
                         output,
                         randomNonce,
                         TagLength,
                         (nonce, cipher, authdata, encrypt) => cipher.Init(encrypt, new AeadParameters(new KeyParameter(AesKeyBytes), TagLength * 8, nonce, authdata)),
                         encrypt: true
                         );
        }

        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns>null as authentication is built in to the encryption</returns>
        public HashingStream GetAuthSigningStream()
        {
            return null;//One stop encrypting and signing;
        }
        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns>null as authentication is built in to the decryption</returns>
        public VerifyingStream GetAuthVerifyingStream()
        {
            return null;//One stop verifying and decrypting
        }

        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetDecryptingStream(Stream output)
        {
           
            return new AesAeadStream(
                GetMode(),
                output,
                new byte[NonceLength], 
                TagLength,
                (nonce, cipher, additionalData, encrypt) => cipher.Init(encrypt, new AeadParameters(new KeyParameter(AesKeyBytes), TagLength * 8, nonce, additionalData)),
                encrypt:false
                );
        }



        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public override void Dispose()
        {
            Secure.Clear(AesKeyBytes);
            AesKeyBytes = null;
        }

      
    }
}
