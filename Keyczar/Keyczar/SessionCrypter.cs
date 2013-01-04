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
using System.IO;
using Keyczar.Compat;
using Keyczar.Crypto;
using Keyczar.Util;
using Newtonsoft.Json;

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
        private AttachedSigner _signer;
        private AttachedVerifier _verifier;
        private byte[] _nonce;

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionCrypter" /> class.
        /// </summary>
        /// <param name="keyEncrypter">The key encrypter.</param>
        /// <param name="signer">The signer, optionally used to certify sender. (Equivialent to SignedSessionEncrypter)</param>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="symmetricKeyType">Type of the symmetric key. (requires unofficial keypacker)</param>
        /// <param name="keyPacker">The key packer.</param>
        /// <exception cref="System.ArgumentException">Without a supplying a keypacker you may only use KeyType.AES;symmetricKeyType</exception>
        public SessionCrypter(Encrypter keyEncrypter, AttachedSigner signer=null, int? keySize=null, KeyType symmetricKeyType = null, ISessionKeyPacker keyPacker = null)
        {
            symmetricKeyType = symmetricKeyType ?? KeyType.Aes;
            if (keyPacker == null && symmetricKeyType != KeyType.Aes)
            {
                throw new ArgumentException("Without a supplying a keypacker you may only use KeyType.AES", "symmetricKeyType");
            }

            if (signer != null)
            {
                keyPacker = keyPacker ?? new NonceSignedSessionPacker();
            }
            keyPacker = keyPacker ?? new SimpleAesHmacSha1KeyPacker();

            dynamic key = Key.Generate(symmetricKeyType, keySize?? symmetricKeyType.DefaultSize); 
            _keyset = new ImportedKeySet(key,KeyPurpose.DecryptAndEncrypt);
            _crypter = new Crypter(_keyset);
            _signer = signer;


            byte[] packedKey;
            var sessionPacker = keyPacker as IInteroperableSessionMaterialPacker;

            if (sessionPacker == null)
            {
                packedKey = keyPacker.Pack(key);
            }
            else
            {
                var nonceSession = new NonceSessionMaterial(key);
                packedKey = sessionPacker.PackMaterial(nonceSession);
                _nonce = nonceSession.Nonce.ToBytes();
            }

            _sessionMaterial = WebBase64.FromBytes(keyEncrypter.Encrypt(packedKey));
            if (sessionPacker == null && _signer !=null)
            {
                _sessionMaterial = WebBase64.FromBytes(_signer.Sign(_sessionMaterial.ToBytes()));
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionCrypter" /> class.
        /// </summary>
        /// <param name="keyDecrypter">The key decrypter.</param>
        /// <param name="sessionMaterial">The session material.</param>
        /// <param name="verifier">The verifier, optionally used to certify sender. (Equivialent to SignedSessionDecrypter)</param>
        /// <param name="keyPacker">The key packer.</param>
        public SessionCrypter(Crypter keyDecrypter, WebBase64 sessionMaterial, AttachedVerifier verifier=null, ISessionKeyPacker keyPacker =null)
        {
            if (verifier != null)
            {
                keyPacker = keyPacker ?? new NonceSignedSessionPacker();
            }
            keyPacker = keyPacker ?? new SimpleAesHmacSha1KeyPacker();

            var sessionMaterialBytes = sessionMaterial.ToBytes();
            var sessionPacker = keyPacker as IInteroperableSessionMaterialPacker;

            _verifier = verifier;

            if (sessionPacker ==null && _verifier != null)
            {
                sessionMaterialBytes = _verifier.VerifiedMessage(sessionMaterialBytes);
            }
            var packedBytes = keyDecrypter.Decrypt(sessionMaterialBytes);

            dynamic key;
            if (sessionPacker == null)
            {
                key = keyPacker.Unpack(packedBytes);
            }
            else
            {
                var nonceSession = sessionPacker.UnpackMaterial(packedBytes);
                key = nonceSession.Key;
                _nonce = nonceSession.Nonce.ToBytes();
            }

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
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = "_signer")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = "_verifier")]
        protected virtual void Dispose(bool disposing)
        {
            _keyset = _keyset.SafeDispose();
            _crypter = _crypter.SafeDispose();
            _signer = _signer.SafeDispose();
            _verifier = _verifier.SafeDispose();
            _nonce = _nonce.Clear();
            _sessionMaterial = _sessionMaterial.Clear(); 
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
             return Keyczar.RawStringEncoding.GetString(Decrypt(data.ToBytes()));
         }

         /// <summary>
         /// Decrypts the specified data.
         /// </summary>
         /// <param name="data">The data.</param>
         /// <returns></returns>
        public byte[] Decrypt(byte[] data)
        {
            using (var output = new MemoryStream())
            using (var input = new MemoryStream(data))
            {
                Decrypt(input, output);
                return output.ToArray();
            }
        }

        /// <summary>
        /// Decrypts the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <exception cref="InvalidCryptoDataException">Can't decrypted, when in signer is provided</exception>
        public void Decrypt(Stream input, Stream output, long inputLength =-1)
        {
            if (_signer != null)
            {
                throw new InvalidCryptoDataException("Can't decrypted, when in signer is provided");
            }
            var finalinput = input;
            if (_verifier != null)
            {
                finalinput = new MemoryStream();
                _verifier.VerifiedMessage(input, finalinput, hidden: _nonce, inputLength: inputLength);
                inputLength = -1;
                finalinput.Seek(0, SeekOrigin.Begin);
            }
            _crypter.Compression = Compression;
            _crypter.Decrypt(finalinput, output, inputLength);
        }

        /// <summary>
        /// Encrypts the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <returns></returns>
        public WebBase64 Encrypt(string rawData)
        {
            return WebBase64.FromBytes(Encrypt(Keyczar.RawStringEncoding.GetBytes(rawData)));
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data)
        {
            using (var output = new MemoryStream())
            using (var input = new MemoryStream(data))
            {
                Encrypt(input, output);
                return output.ToArray();
            }
        }

        /// <summary>
        /// Encrypts the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <exception cref="InvalidCryptoDataException">Can't encrypt, when verifier is provided</exception>
        public void Encrypt(Stream input, Stream output, long inputLength = -1)
        {
            if (_verifier != null)
            {
                throw new InvalidCryptoDataException("Can't encrypt, when verifier is provided");
            }
            _crypter.Compression = Compression;

            Stream finaloutput = output;
            if (_signer != null)
            {
                output = new MemoryStream();
            }
            _crypter.Encrypt(input, output, inputLength);
            if (_signer != null)
            {
                output.Seek(0, SeekOrigin.Begin);
                _signer.Sign(output, finaloutput, hidden: _nonce);
            }
        }


       private static readonly int SessionNonceSize = 16;

       /// <summary>
       /// Nonce Json Session Material;
       /// </summary>
        public class NonceSessionMaterial
        {

            /// <summary>
            /// Initializes a new instance of the <see cref="NonceSessionMaterial" /> class.
            /// </summary>
            public NonceSessionMaterial()
            {
                
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="NonceSessionMaterial" /> class.
            /// </summary>
            /// <param name="key">The key.</param>
            public NonceSessionMaterial(AesKey key)
            {
                Key = key;
                var nonce= new byte[SessionNonceSize];
                Secure.Random.NextBytes(nonce);
                Nonce = WebBase64.FromBytes(nonce);
            }

            /// <summary>
            /// Gets or sets the key.
            /// </summary>
            /// <value>
            /// The key.
            /// </value>
            public AesKey Key { get; set; }
            /// <summary>
            /// Gets or sets the nonce.
            /// </summary>
            /// <value>
            /// The nonce.
            /// </value>
            public WebBase64 Nonce { get; set; }
        }

        /// <summary>
        /// Interface for special cased keyczar defined signed sessions.
        /// </summary>
        internal interface IInteroperableSessionMaterialPacker
        {
            /// <summary>
            /// Packs the material.
            /// </summary>
            /// <param name="material">The material.</param>
            /// <returns></returns>
            byte[] PackMaterial(NonceSessionMaterial material);

            /// <summary>
            /// Unpacks the material.
            /// </summary>
            /// <param name="data">The data.</param>
            /// <returns></returns>
            NonceSessionMaterial UnpackMaterial(byte[] data);
        }

        /// <summary>
        /// Standard key packer for SignedSessions, only packs AES-Then-HmacSha1
        /// </summary>
        public class NonceSignedSessionPacker : ISessionKeyPacker, IInteroperableSessionMaterialPacker
        {
            /// <summary>
            /// Packs the specified key into bytes
            /// </summary>
            /// <param name="key">The key.</param>
            /// <returns></returns>
            byte[] ISessionKeyPacker.Pack(Key key)
            {
                return PackMaterial(new NonceSessionMaterial(key as AesKey));
            }

            /// <summary>
            /// Unpacks the specified bytes into a key.
            /// </summary>
            /// <param name="data">The bytes.</param>
            /// <returns></returns>
            Key ISessionKeyPacker.Unpack(byte[] data)
            {
                return UnpackMaterial(data).Key;
            }


            /// <summary>
            /// Packs the material.
            /// </summary>
            /// <param name="material">The material.</param>
            /// <returns></returns>
            public byte[] PackMaterial(NonceSessionMaterial material)
            {
                string json = material.ToJson();
                return Keyczar.RawStringEncoding.GetBytes(json);
            }

            /// <summary>
            /// Unpacks the material.
            /// </summary>
            /// <param name="data">The data.</param>
            /// <returns></returns>
            public NonceSessionMaterial UnpackMaterial(byte[] data)
            {
                return (NonceSessionMaterial)JsonConvert.DeserializeObject(Keyczar.RawStringEncoding.GetString(data), typeof(NonceSessionMaterial));
            }
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
