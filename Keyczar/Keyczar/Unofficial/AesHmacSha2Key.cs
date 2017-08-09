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

using System.Collections.Generic;
using System.IO;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Encrypts AES
    /// </summary>
    public class AesHmacSha2Key : Key, ICrypterKey
    {
        /// <summary>
        /// Block size is 128bits
        /// </summary>
        [JsonIgnore] public readonly int BlockLength = 16;

        /// <summary>
        /// Gets or sets the mode only CBC supported.
        /// </summary>
        /// <value>The block cipher mode.</value>
        public string Mode { get; set; }

        /// <summary>
        /// Gets or sets the aes key bytes.
        /// </summary>
        /// <value>The aes key bytes.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance",
            "CA1819:PropertiesShouldNotReturnArrays"), JsonConverter(typeof (WebSafeBase64ByteConverter))]
        [JsonProperty("AesKeyString")]
        public byte[] AesKeyBytes { get; set; }

        /// <summary>
        /// Gets or sets the hmac key.
        /// </summary>
        /// <value>The hmac key.</value>
        public HmacSha2Key HmacKey { get; set; }

        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash() 
            => Utility.HashKey(KeyczarConst.KeyHashLength, Utility.GetBytes(AesKeyBytes.Length), AesKeyBytes,
                    HmacKey.HmacKeyBytes, Utility.GetBytes(HmacKey.HashLength), HmacKey.Digest.ToBytes());

        /// <summary>
        /// Gets the fallback key hashes. old/buggy hashes from old/other keyczar implementations
        /// </summary>
        /// <returns></returns>
        public override IEnumerable<byte[]> GetFallbackKeyHash()
        {
            var trimmedKeyBytes = Utility.StripLeadingZeros(AesKeyBytes);
            return new byte[][]
                       {
                           //Java keyczar uses block length instead of keylength for hash
                           Utility.HashKey(KeyczarConst.KeyHashLength, Utility.GetBytes(BlockLength), AesKeyBytes,
                                           HmacKey.HmacKeyBytes, HmacKey.Digest.ToBytes()),
                           //c++ keyczar used to strip leading zeros from key bytes
                           Utility.HashKey(KeyczarConst.KeyHashLength, Utility.GetBytes(trimmedKeyBytes.Length),
                                           trimmedKeyBytes,
                                           HmacKey.HmacKeyBytes),
                       };
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesKey"/> class.
        /// </summary>
        public AesHmacSha2Key()
        {
            Mode = "CBC"; //Default Mode
        }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size)
        {
            AesKeyBytes = new byte[size/8];
            Secure.Random.NextBytes(AesKeyBytes);
            HmacKey = (HmacSha2Key) Generate(UnofficialKeyType.HmacSha2, size);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            Mode = null;
            AesKeyBytes = AesKeyBytes.Clear();
            HmacKey = HmacKey.SafeDispose();
        }


        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns></returns>
        public HashingStream GetAuthSigningStream(KeyczarBase keyczar) 
            => HmacKey.GetSigningStream(keyczar);

        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns></returns>
        public VerifyingStream GetAuthVerifyingStream(KeyczarBase keyczar) 
            => HmacKey.GetVerifyingStream(keyczar);


        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public virtual FinishingStream GetEncryptingStream(Stream output,KeyczarBase keyczar)
        {
            var ivarr = new byte[BlockLength];
            Secure.Random.NextBytes(ivarr);
            return new SymmetricStream(
                new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
                output,
                ivarr,
                HmacKey.HashLength,
                (iv, cipher, encrypt) =>
                cipher.Init(forEncryption: encrypt, parameters: new ParametersWithIV(new KeyParameter(AesKeyBytes), iv)),
                encrypt: true);
        }

        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public virtual FinishingStream GetDecryptingStream(Stream output,KeyczarBase keyczar)
        {
            return new SymmetricStream(
                new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
                output,
                new byte[BlockLength],
                HmacKey.HashLength,
                (iv, cipher, encrypt) =>
                cipher.Init(forEncryption: encrypt, parameters: new ParametersWithIV(new KeyParameter(AesKeyBytes), iv)),
                encrypt: false);
        }
    }
}