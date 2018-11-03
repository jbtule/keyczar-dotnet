﻿/*  Copyright 2012 James Tuley (jay+code@tuley.name)
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
using System.ComponentModel;
using System.IO;
using System.Text;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Uses Authenticated Encryption with Associated Data Mode with AES.
    /// Specficially supports GCM mode.
    /// </summary>
    public class AesAeadKey : Key, ICrypterKey
    {
        /// <summary>
        /// Uses 128bit block size
        /// </summary>
        [JsonIgnore] public readonly int BlockLength = 16;

        /// <summary>
        /// Uses 128bit MAC
        /// </summary>
        [JsonIgnore] public readonly int TagLength = 16;

        /// <summary>
        /// Gets or sets the length of the IV.
        /// </summary>
        /// <value>
        /// The length of the IV.
        /// </value>
        [DefaultValue(16)]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
        public int IVLength { get; set; }

        /// <summary>
        /// Gets or sets the mode (Only GCM is supported).
        /// </summary>
        /// <value>The mode.</value>
        public AesMode Mode { get; set; }


        /// <summary>
        /// The GCM mode
        /// </summary>
        [Obsolete("Use AesMode.Gcm instead.")]
        public static readonly string GcmMode = "GCM";

        /// <summary>
        /// Initializes a new instance of the <see cref="AesAeadKey"/> class.
        /// </summary>
        public AesAeadKey()
        {
            Mode = AesMode.Gcm; //Default Mode
            IVLength = 12;
        }

        /// <summary>
        /// Gets or sets the aes key bytes.
        /// </summary>
        /// <value>The aes key bytes.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance",
            "CA1819:PropertiesShouldNotReturnArrays")]
        [JsonConverter(typeof (WebSafeBase64ByteConverter))]
        [JsonProperty("AesKeyString")]
        public byte[] AesKeyBytes { get; set; }

        /// <summary>
        /// Generates the key.
        /// </summary>
        /// <param name="size">The size.</param>
        protected override void GenerateKey(int size, KeyczarConfig config)
        {
            AesKeyBytes = new byte[size/8];
            Secure.Random.NextBytes(AesKeyBytes);
        }

        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] GetKeyHash()
        {
            return GenerateKeyHash(AesKeyBytes, IVLength, Mode);
    
        }

        public static byte[] GenerateKeyHash(byte[] keyBytes, int ivLength, AesMode mode)
        {
            return Utility.UnofficalHashKey(KeyczarConst.KeyHashLength, Utility.GetBytes(keyBytes.Length),
                mode.ToBytes(), Utility.GetBytes(ivLength), keyBytes);
        }

        /// <summary>
        /// Gets the fallback key hashes. old/buggy hashes from old/other keyczar implementations
        /// </summary>
        /// <returns></returns>
        public override IEnumerable<byte[]> GetFallbackKeyHash()
        {
            var list = new List<byte[]>();
            if (IVLength == 16 && Mode == AesMode.Gcm)
            {
                //Pre IVLength property existing key hash
                list.Add(Utility.HashKey(KeyczarConst.KeyHashLength, Utility.GetBytes(AesKeyBytes.Length),
                                         Mode.ToBytes(), AesKeyBytes));
            }
            
            list.Add(Utility.HashKey(KeyczarConst.KeyHashLength, Utility.GetBytes(AesKeyBytes.Length),
                Mode.ToBytes(), Utility.GetBytes(IVLength), AesKeyBytes));
            
            return list;
        }

        private Func<IAeadBlockCipher> GetMode()
        {
            if (Mode == AesMode.Gcm)
            {
                return () => _cipher;
            }
            throw new InvalidKeyTypeException("Unsupported AES AEAD Mode: " + Mode);
        }

        private KeyParameter _keyParm;

        private KeyParameter GetKeyParameters()
        {
            return _keyParm ?? (_keyParm = new KeyParameter(AesKeyBytes));
        }


        private readonly GcmBlockCipher _cipher = new GcmBlockCipher(new AesEngine(), new Tables8kGcmMultiplier());

        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetEncryptingStream(Stream output,KeyczarBase keyczar)
        {
            var randomNonce = new byte[IVLength];
            Secure.Random.NextBytes(randomNonce);
            return new SymmetricAeadStream(
                GetMode(),
                output,
                randomNonce,
                TagLength,
                (nonce, cipher, authdata, encrypt) =>
                cipher.Init(encrypt, new AeadParameters(GetKeyParameters(), TagLength*8, nonce, authdata)),
                encrypt: true
                );
        }

        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns>null as authentication is built in to the encryption</returns>
        public HashingStream GetAuthSigningStream(KeyczarBase keyczar) => null;

        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns>null as authentication is built in to the decryption</returns>
        public VerifyingStream GetAuthVerifyingStream(KeyczarBase keyczar) => null;

        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public FinishingStream GetDecryptingStream(Stream output,KeyczarBase keyczar) 
            => new SymmetricAeadStream(
                    GetMode(),
                    output,
                    new byte[IVLength],
                    TagLength,
                    (nonce, cipher, additionalData, encrypt) =>
                        cipher.Init(encrypt, new AeadParameters(GetKeyParameters(), TagLength*8, nonce, additionalData)),
                    encrypt: false
                );


        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            _keyParm = null;
            _cipher.Reset();
            AesKeyBytes = AesKeyBytes.Clear();
        }
    }
}