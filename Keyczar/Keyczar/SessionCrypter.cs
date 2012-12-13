/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * 
 * 8/2012 Direct Ported to C#. Modified for replaceable key packing format - jay+code@tuley.name (James Tuley)
 * 
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Compat;
using Keyczar.Crypto;
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Interface for mechanisms to pack a key into an array
    /// </summary>
    public interface ISessionKeyPacker
    {
        /// <summary>
        /// Packs the specified key into bytes
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        byte[] Pack(Key key);

        /// <summary>
        /// Unpacks the specified bytes into a key.
        /// </summary>
        /// <param name="data">The bytes.</param>
        /// <returns></returns>
        Key Unpack(byte[] data);
    }

    /// <summary>
    /// Crypter for Asymmetic key exchange and Symmetric encryption
    /// </summary>
    public class SessionCrypter:IDisposable
    {
        private Crypter _crypter;
        private WebBase64 _sessionMaterial;
        private ImportedKeySet _keyset;

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionCrypter" /> class.
        /// </summary>
        /// <param name="keyEncrypter">The key encrypter.</param>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="symmetricKeyType">Type of the symmetric key. (requires keypacker)</param>
        /// <param name="keyPacker">The key packer.</param>
        /// <exception cref="System.ArgumentException">Without a supplying a keypacker you may only use KeyType.AES;symmetricKeyType</exception>
        public SessionCrypter(Encrypter keyEncrypter, int? keySize=null, KeyType symmetricKeyType = null, ISessionKeyPacker keyPacker = null)
        {
            symmetricKeyType = symmetricKeyType ?? KeyType.Aes;
            if (keyPacker == null && symmetricKeyType != KeyType.Aes)
            {
                throw new ArgumentException("Without a supplying a keypacker you may only use KeyType.AES", "symmetricKeyType");
            }
            keyPacker = keyPacker ?? new SimpleAesHmacSha1KeyPacker();
            dynamic key = Key.Generate(symmetricKeyType, keySize?? symmetricKeyType.DefaultSize); 
            _keyset = new ImportedKeySet(key,KeyPurpose.DecryptAndEncrypt);
            _crypter = new Crypter(_keyset);
            _sessionMaterial = WebBase64.FromBytes(keyEncrypter.Encrypt(keyPacker.Pack(key)));


        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionCrypter"/> class.
        /// </summary>
        /// <param name="keyDecrypter">The key decrypter.</param>
        /// <param name="sessionMaterial">The session material.</param>
        /// <param name="keyPacker">The key packer.</param>
        public SessionCrypter(Crypter keyDecrypter, WebBase64 sessionMaterial, ISessionKeyPacker keyPacker =null)
        {
            keyPacker = keyPacker ?? new SimpleAesHmacSha1KeyPacker();
			var packedBytes =keyDecrypter.Decrypt(sessionMaterial.ToBytes());
			dynamic key =keyPacker.Unpack(packedBytes);
            _keyset = new ImportedKeySet(key, KeyPurpose.DecryptAndEncrypt);
            _crypter = new Crypter(_keyset);
            _sessionMaterial = sessionMaterial;
        }

        /// <summary>
        /// Gets the session material.
        /// </summary>
        /// <value>The session material.</value>
        public WebBase64 SessionMaterial
        {
            get { return _sessionMaterial; }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
                    GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="SessionCrypter" /> class.
        /// </summary>
        ~SessionCrypter()
        {
            Dispose(false);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = "_crypter")]
        protected virtual void Dispose(bool disposing)
        {
            _keyset = _keyset.SafeDispose();
            _crypter = _crypter.SafeDispose();
            _sessionMaterial = SessionMaterial.Clear(); 
        }

        /// <summary>
        /// Gets or sets the compression.
        /// </summary>
        /// <value>The compression.</value>
        public CompressionType Compression
        {
            get;
            set;
        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
         public string Decrypt(WebBase64 data)
        {
            _crypter.Compression = Compression;
             return _crypter.Decrypt(data);
         }

         /// <summary>
         /// Decrypts the specified data.
         /// </summary>
         /// <param name="data">The data.</param>
         /// <returns></returns>
        public byte[] Decrypt(byte[] data)
         {
             _crypter.Compression = Compression;
            return _crypter.Decrypt(data);
        }

        /// <summary>
        /// Decrypts the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        public void Decrypt(Stream input, Stream output, long inputLength =-1)
        {
            _crypter.Compression = Compression;
            _crypter.Decrypt(input, output, inputLength);
        }

        /// <summary>
        /// Encrypts the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <returns></returns>
        public WebBase64 Encrypt(string rawData)
        {
            _crypter.Compression = Compression;
            return _crypter.Encrypt(rawData);
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data)
        {
            _crypter.Compression = Compression;
            return _crypter.Encrypt(data);
        }

        /// <summary>
        /// Encrypts the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        public void Encrypt(Stream input, Stream output, long inputLength = -1)
        {
            _crypter.Compression = Compression;
            _crypter.Encrypt(input, output, inputLength);
        }

        /// <summary>
        /// Standard key packer, only packs AES-Then-HmacSha1
        /// </summary>
        public class SimpleAesHmacSha1KeyPacker : ISessionKeyPacker
        {
            /// <summary>
            /// Packs the specified key into bytes
            /// </summary>
            /// <param name="key">The key.</param>
            /// <returns></returns>
            public byte[] Pack(Key key)
            {
                var aesKey = key as AesKey;
                var inputArrays = new byte[][] { aesKey.AesKeyBytes, aesKey.HmacKey.HmacKeyBytes };
                           // Count an int for each input array
                int outputSize = (1 + inputArrays.Length) * 4;
                foreach (var array in inputArrays)
                {
                    outputSize += array.Length;
                }
               
               byte[] output = new byte[outputSize];
               using(Stream outputBuffer = new MemoryStream(output))
               {
                   // Put the number of total arrays
                   byte[] length = Utility.GetBytes(inputArrays.Length);
                   outputBuffer.Write(length,0,length.Length);
                   foreach (var array in inputArrays)
                   {
                       // Put the size of this array
                       byte[] alength = Utility.GetBytes(array.Length);
                       outputBuffer.Write(alength, 0, alength.Length);
                       // Put the array itself
                       outputBuffer.Write(array, 0, array.Length);
                   }
                   return output;
               }
            }


            /// <summary>
            /// Unpacks the specified bytes into a key.
            /// </summary>
            /// <param name="data">The bytes.</param>
            /// <returns></returns>
            public Key Unpack(byte[] data)
            {
                using (Stream input = new MemoryStream(data))
                {
                    var lengthBuffer = new byte[4];
                    input.Read(lengthBuffer, 0, lengthBuffer.Length);
                    int numArrays = Utility.ToInt32(lengthBuffer);
                    byte[][] output = new byte[numArrays][];
                    for (int i = 0; i < numArrays; i++)
                    {
                        input.Read(lengthBuffer, 0, lengthBuffer.Length);
                        int len = Utility.ToInt32(lengthBuffer);
                        byte[] array = new byte[len];
                        input.Read(array, 0, array.Length);
                        output[i] = array;
                    }
                    return new AesKey()
                               {
                                   AesKeyBytes = output[0],
                                   HmacKey = new HmacSha1Key() {HmacKeyBytes = output[1]},
                                   Mode = "CBC"
                               };
                }
            }
        }
    }

 
 
}
