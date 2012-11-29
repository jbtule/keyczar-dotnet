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
    /// Signs data using a given keyset
    /// </summary>
    public class Signer:Verifier
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Signer"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public Signer(string keySetLocation) : this(new KeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Signer" /> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <exception cref="InvalidKeySetException">This key set can not be used for signing and verifying.</exception>
        public Signer(IKeySet keySet) : base(keySet)
        {
            if (keySet.Metadata.Purpose != KeyPurpose.SIGN_AND_VERIFY)
            {
                throw new InvalidKeySetException("This key set can not be used for signing and verifying.");
            }
        }

        /// <summary>
        /// Signs the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <returns></returns>
        public WebBase64 Sign(String rawData)
        {
			return WebBase64.FromBytes(Sign(DefaultEncoding.GetBytes(rawData)));
           
        }

        /// <summary>
        /// Signs the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <returns></returns>
        public byte[] Sign(byte[] rawData)
        {
            using (var memstream = new MemoryStream(rawData))
            {
                return Sign(memstream);
            }
        }

        /// <summary>
        /// Signs the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] Sign(Stream data)
        {
			using(var stream = new MemoryStream()){
            	Sign(data, stream, prefixData: null, postfixData: null, signatureData: null);
				stream.Flush();
				return stream.ToArray();
			}
        }

        /// <summary>
        /// Signs the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="outstream">The outstream.</param>
        /// <param name="prefixData">The prefix data.</param>
        /// <param name="postfixData">The postfix data.</param>
        /// <param name="signatureData">The sig data.</param>
        protected void Sign(Stream data, Stream outstream, object prefixData, object postfixData, object signatureData)
        {
            var key = GetPrimaryKey() as ISignerKey;
            using (var reader = new NondestructiveBinaryReader(data))
            {
                using (var signingStream = key.GetSigningStream())
                {
                    PrefixDataSign(signingStream, prefixData);
                    while (reader.Peek() != -1)
                    {
                        byte[] buffer = reader.ReadBytes(BUFFER_SIZE);
                        signingStream.Write(buffer, 0, buffer.Length);
                    }
                    PostfixDataSign(signingStream, postfixData);
                    signingStream.Finish();

                    var signature = signingStream.HashValue;
                    PadSignature(signature, outstream, signatureData);
                }
            }
        }

        /// <summary>
        /// Prefixes the data then signs it.
        /// </summary>
        /// <param name="signingStream">The signing stream.</param>
        /// <param name="extra">The extra data passed by prefixData.</param>
        protected virtual void PrefixDataSign(HashingStream signingStream, object extra)
        {

        }

        /// <summary>
        /// Postfixes the data then signs it.
        /// </summary>
        /// <param name="signingStream">The signing stream.</param>
        /// <param name="extra">The extra data passed by postfixData.</param>
        protected virtual void PostfixDataSign(HashingStream signingStream, object extra)
        {
            signingStream.Write(FORMAT_BYTES, 0, FORMAT_BYTES.Length);
        }

        /// <summary>
        /// Pads the signature with extra data.
        /// </summary>
        /// <param name="signature">The signature.</param>
		/// <param name="outputStream">The padded signature.</param>
        /// <param name="extra">The extra data passed by sigData.</param>
        /// <returns></returns>
        protected virtual void PadSignature(byte[] signature, Stream outputStream, object extra)
        {
            var key = GetPrimaryKey() as ISignerKey;
			outputStream.Write(FORMAT_BYTES,0,FORMAT_BYTES.Length);
			outputStream.Write(key.GetKeyHash(),0,KEY_HASH_LENGTH);
			outputStream.Write(signature,0,signature.Length);
        }

    }
}
