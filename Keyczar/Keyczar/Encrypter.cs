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
    /// Types of compression for plaintext
    /// </summary>
    public enum CompressionType{
        /// <summary>
        /// None
        /// </summary>
        None =0,
        /// <summary>
        /// Gzip compression
        /// </summary>
        Gzip =1,
        /// <summary>
        /// Zlib compression
        /// </summary>
        Zlib =2,
    }

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
        /// Initializes a new instance of the <see cref="Encrypter" /> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <exception cref="InvalidKeySetException">This key set can not be used for encryption.</exception>
        public Encrypter(IKeySet keySet) : base(keySet)
        {

            if (keySet.Metadata.Purpose != KeyPurpose.Encrypt
                && keySet.Metadata.Purpose != KeyPurpose.DecryptAndEncrypt)
            {
                throw new InvalidKeySetException("This key set can not be used for encryption.");
            }

        }

        /// <summary>
        /// Gets or sets the compression.
        /// </summary>
        /// <value>The compression.</value>
        public CompressionType Compression{
            get;set;
        }

        /// <summary>
        /// Encrypts the specified raw string data.
        /// </summary>
        /// <param name="rawData">The raw string data.</param>
        /// <returns></returns>
        public WebBase64 Encrypt(string rawData)
        {
            return WebBase64.FromBytes(Encrypt(RawStringEncoding.GetBytes(rawData)));
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
        /// <param name="inputLength">(optional) Length of the input.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
        public void Encrypt(Stream input, Stream output, long inputLength= -1)
        {
            var stopLength = inputLength < 0 ? long.MaxValue : input.Position + inputLength;
            var key = GetPrimaryKey();
            var header = new byte[HeaderLength];
            Array.Copy(FormatBytes,0,header,0,FormatBytes.Length);
            Array.Copy(key.GetKeyHash(), 0, header, FormatBytes.Length, KeyHashLength);
           
            var cryptKey = key as IEncrypterKey;

            var resetStream = Utility.ResetStreamWhenFinished(output);
            using (var reader = new NondestructiveBinaryReader(input))
            {
                FinishingStream encryptingStream;

             
                output.Write(header, 0, header.Length);
                encryptingStream = cryptKey.GetEncryptingStream(output);
               

                Stream wrapper = encryptingStream;
                if(Compression == CompressionType.Gzip){
                    wrapper = new GZipStream(encryptingStream,CompressionMode.Compress,true);
                }else if(Compression == CompressionType.Zlib){
                    wrapper = new ZlibStream(encryptingStream,CompressionMode.Compress,true);
                }

                using (encryptingStream)
                {
                    encryptingStream.GetTagLength(header);
                    using(Compression == CompressionType.None ? null : wrapper){
                        while (reader.Peek() != -1 && input.Position < stopLength)
                        {
                            var adjustedBufferSize = (int)Math.Min(BufferSize, (stopLength - input.Position));
                            byte[] buffer = reader.ReadBytes(adjustedBufferSize);
                            wrapper.Write(buffer, 0, buffer.Length);
                        }
                    }
                    encryptingStream.Finish();
                }
            }

           
            byte[] hash;
            using (var outputReader = new NondestructiveBinaryReader(output))
            using (var signingStream = cryptKey.GetAuthSigningStream())
            {
                if (signingStream == null || signingStream.GetTagLength(header) ==0)
                    return;
                resetStream.Reset();
                while (outputReader.Peek() != -1)
                {
                    byte[] buffer = outputReader.ReadBytes(BufferSize);
                    signingStream.Write(buffer, 0, buffer.Length);
                }
                signingStream.Finish();

                hash = signingStream.HashValue;
            }
                
            output.Write(hash, 0, hash.Length);
            
        }
    }
}
