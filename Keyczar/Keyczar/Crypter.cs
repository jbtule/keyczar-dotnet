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
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Ionic.Zlib;

namespace Keyczar
{
    /// <summary>
    /// Used to encrypt or decrypt data using a given key set.
    /// </summary>
    public class Crypter : Encrypter
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Crypter"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public Crypter(string keySetLocation)
             : this(new KeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Crypter"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        public Crypter(IKeySet keySet)
            : base(keySet)
        {
            if (keySet.Metadata.Purpose != KeyPurpose.DecryptAndEncrypt)
            {
                throw new InvalidKeySetException("This key set can not be used for decryption and encryption.");
            }
        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public string Decrypt(WebBase64 data)
        {
            return RawStringEncoding.GetString(Decrypt(data.ToBytes()));
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
        /// <exception cref="InvalidCryptoDataException">Ciphertext was invalid!</exception>
        public void Decrypt(Stream input, Stream output, long inputLength = -1)
        {
            var fullLength = inputLength < 0 ? input.Length : inputLength + input.Position;
            using (var reader = new NondestructiveBinaryReader(input))
            {
                byte[] keyHash;
                var resetStream = Utility.ResetStreamWhenFinished(input);
                var header = Utility.ReadHeader(input, out keyHash);
                var verify = true;

                foreach (var key in GetKey(keyHash))
                {

                    var cryptKey = key as ICrypterKey;
                    var pbeKey = cryptKey as IPbeKey;
                    resetStream.Reset();
                


                    //in case there aren't any keys that match that hash we are going to fake verify.
                    using (var verifyStream = cryptKey.Maybe(m => m.GetAuthVerifyingStream(), () => new DummyStream()))
                    {
                        //If we verify in once pass like with AEAD verify stream will be null;
                        if (verifyStream != null)
                        {
                            var tagLength = verifyStream.GetTagLength(header);
                            while (input.Position < fullLength - tagLength)
                            {
                                byte[] buffer =
                                    reader.ReadBytes((int)Math.Min(BufferSize, fullLength - tagLength - input.Position));
                                verifyStream.Write(buffer, 0, buffer.Length);
                            }
                            var signature = reader.ReadBytes(tagLength);

                            verify = verifyStream.VerifySignature(signature);
                        }
                    }

                    if (!verify || input.Length == 0)
                    {
                        continue;
                    }

					Stream wrapper = output;
					if(Compression == CompressionType.Gzip){
						wrapper = new WriteDecompressGzipStream(output);
					}else if(Compression == CompressionType.Zlib){
						wrapper = new ZlibStream(output,CompressionMode.Decompress,true);
					}
					using(Compression == CompressionType.None ? null : wrapper){
                        FinishingStream crypterStream; 
                        resetStream.Reset();
	                    if (pbeKey != null)
	                    {
							crypterStream = pbeKey.GetRawDecryptingStream(wrapper);
	                    }
	                    else
	                    {
	                        input.Seek(HeaderLength, SeekOrigin.Current);
							crypterStream = cryptKey.Maybe(m => m.GetDecryptingStream(wrapper), () => new DummyStream());
	                    }
					    try
					    {
					        using (crypterStream)
					        {
					            var tagLength = crypterStream.GetTagLength(header);
					            while (input.Position < fullLength - tagLength)
					            {
					                byte[] buffer =
					                    reader.ReadBytes((int) Math.Min(BufferSize, fullLength - tagLength - input.Position));
					                crypterStream.Write(buffer, 0, buffer.Length);
					            }
					            crypterStream.Finish();
					            input.Seek(tagLength, SeekOrigin.Current);
					        }
					        return;
					    }
					    catch (InvalidCryptoDataException)
					    {
					        verify = false;
					    }
					}

                }
                if (!verify)
                {
                    throw new InvalidCryptoDataException("Cipher text was invalid!");
                }
            }
        }
    }
}
