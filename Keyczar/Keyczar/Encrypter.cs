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

namespace Keyczar
{
    /// <summary>
    ///  Encrypts data using a given key set.
    /// </summary>
    public class Encrypter:Keyczar
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Encrypter"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public Encrypter(string keySetLocation)
            : this(new KeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Encrypter"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        public Encrypter(IKeySet keySet) : base(keySet)
        {

            if (keySet.Metadata.Purpose != KeyPurpose.ENCRYPT
                && keySet.Metadata.Purpose != KeyPurpose.DECRYPT_AND_ENCRYPT)
            {
                throw new InvalidKeyTypeException("This key set can not be used for encryption.");
            }

        }

        /// <summary>
        /// Encrypts the specified raw string data.
        /// </summary>
        /// <param name="rawData">The raw string data.</param>
        /// <returns></returns>
        public string Encrypt(string rawData)
        {
            return new String(WebSafeBase64.Encode(Encrypt(DefaultEncoding.GetBytes(rawData))));
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data)
        {
            using(var output = new MemoryStream())
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
        public void Encrypt(Stream input, Stream output)
        {

            var key = GetPrimaryKey();
            var header = new byte[HEADER_LENGTH];
            Array.Copy(FORMAT_BYTES,0,header,0,FORMAT_BYTES.Length);
            Array.Copy(key.GetKeyHash(), 0, header, FORMAT_BYTES.Length, KEY_HASH_LENGTH);
           
            var cryptKey = key as IEncrypterKey;
            var pbeKey = key as IPbeKey;

            using (var reader = new NonDestructiveBinaryReader(input))
            {
                FinishingStream encryptingStream; 
                if (pbeKey == null)
                {
                    output.Write(header, 0, header.Length);
                    encryptingStream = cryptKey.GetEncryptingStream(output);
                }else
                {
                    encryptingStream = pbeKey.GetRawEncryptingStream(output);
                }
                using (encryptingStream)
                {
                    encryptingStream.GetTagLength(header);

                    while (reader.Peek() != -1)
                    {
                        byte[] buffer = reader.ReadBytes(4096);
                        encryptingStream.Write(buffer, 0, buffer.Length);
                    }
                    encryptingStream.Finish();
                }
            }
           
            byte[] hash;
            using (var outputReader = new NonDestructiveBinaryReader(output))
            using (var signingStream = cryptKey.GetAuthSigningStream())
            {
                if (signingStream == null || signingStream.GetTagLength(header) ==0)
                    return;
                output.Seek(0, SeekOrigin.Begin);
                while (outputReader.Peek() != -1)
                {
                    byte[] buffer = outputReader.ReadBytes(BUFFER_SIZE);
                    signingStream.Write(buffer, 0, buffer.Length);
                }
                signingStream.Finish();

                hash = signingStream.HashValue;
            }
                
            output.Write(hash, 0, hash.Length);
            
        }
    }
}
