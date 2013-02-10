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
    /// Verifies signed data using a given key set.
    /// </summary>
    public class Verifier:Keyczar
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Verifier"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public Verifier(string keySetLocation)
            : this(new KeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Verifier" /> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <exception cref="InvalidKeySetException">This key set can not be used for verifying signatures.</exception>
        public Verifier(IKeySet keySet) : base(keySet)
        {
            if (keySet.Metadata.Purpose != KeyPurpose.Verify
                && keySet.Metadata.Purpose != KeyPurpose.SignAndVerify)
            {
                throw new InvalidKeySetException("This key set can not be used for verifying signatures.");
            }
        }

        /// <summary>
        /// Verifies the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        public bool Verify(string rawData, WebBase64 signature)
        {
			return Verify(RawStringEncoding.GetBytes(rawData), signature.ToBytes());
        }

        /// <summary>
        /// Verifies the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        public bool Verify(byte[] rawData, byte[] signature)
        {
            using (var memstream = new MemoryStream(rawData))
            {
                return Verify(memstream, signature);
            }
        }

        /// <summary>
        /// Gets the keys.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <param name="trimmedSignature">The trimmed sig.</param>
        /// <returns></returns>
        /// <exception cref="InvalidCryptoDataException">Signature missing header information.</exception>
        protected virtual IEnumerable<IVerifierKey> GetKeys( byte[] signature, out byte[] trimmedSignature)
        {
            if(signature.Length < HeaderLength)
                throw new InvalidCryptoDataException("Signature missing header information.");

            byte[] keyHash;
            Utility.ReadHeader(signature, out keyHash);
            trimmedSignature = new byte[signature.Length - HeaderLength];
            Array.Copy(signature, HeaderLength, trimmedSignature, 0, trimmedSignature.Length);
            var keys = GetKey(keyHash);
            return keys.Select(it=>it as IVerifierKey);
        }

        /// <summary>
        /// Verifies the specified data.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <returns></returns>
        public bool Verify(Stream input, byte[] signature, long inputLength = -1)
        {
            return Verify(input, signature, inputLength:inputLength, prefixData: null, postfixData: null);
        }

        /// <summary>
        /// Prefixes the data before verifying.
        /// </summary>
        /// <param name="verifyingStream">The verifying stream.</param>
        /// <param name="extra">The extra data passed by prefixData</param>
        protected virtual void PrefixDataVerify(VerifyingStream verifyingStream, object extra)
        {
            
        }
        /// <summary>
        /// Postfixes data before verifying.
        /// </summary>
        /// <param name="verifyingStream">The verifying stream.</param>
        /// <param name="extra">The extra data passed by postfixData</param>
        protected virtual void PostfixDataVerify(VerifyingStream verifyingStream, object extra)
        {
            verifyingStream.Write(FormatBytes, 0, FormatBytes.Length);
        }

        /// <summary>
        /// Verifies the specified data.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="prefixData">The prefix data.</param>
        /// <param name="postfixData">The postfix data.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <returns></returns>
        protected virtual bool Verify(Stream input, byte[] signature, object prefixData, object postfixData, long inputLength)
        {
            var stopLength = inputLength < 0 ? long.MaxValue : input.Position + inputLength;
            using (var reader = new NondestructiveBinaryReader(input))
            {
                byte[] trimmedSig;
                var resetData = Utility.ResetStreamWhenFinished(input);
                foreach (var key in GetKeys(signature, out trimmedSig))
                {
                    resetData.Reset();
                    //in case there aren't any keys that match that hash we are going to fake verify.
                    using (var verifyStream = key.Maybe(m => m.GetVerifyingStream(), () => new DummyStream()))
                    {
                        PrefixDataVerify(verifyStream,prefixData);
                        while (reader.Peek() != -1 && input.Position < stopLength)
                        {
                            var adjustedBufferSize = (int)Math.Min(BufferSize, (stopLength - input.Position));
                            byte[] buffer = reader.ReadBytes(adjustedBufferSize);
                            verifyStream.Write(buffer, 0, buffer.Length);
                        }
                            PostfixDataVerify(verifyStream,postfixData);

                        try
                        {


                            if (verifyStream.VerifySignature(trimmedSig))
                            {
                                return true;
                            }
                        }
                        catch (Exception e)
                        {      
                            //We don't want exceptions to keep us from trying different keys
                            System.Diagnostics.Debug.WriteLine(e.Message);
                            System.Diagnostics.Debug.WriteLine(e.StackTrace);
                        }
                    }

                }
                return false;
            }
        }

    }
}
