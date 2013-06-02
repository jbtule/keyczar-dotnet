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
using System.IO;
using Keyczar.Crypto;
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Signs a message and attaches the signature
    /// </summary>
    public class AttachedSigner:AttachedVerifier
    {
        private AttachedSignerHelper _signer;

        /// <summary>
        /// Initializes a new instance of the <see cref="AttachedSigner"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public AttachedSigner(string keySetLocation) : this(new KeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AttachedSigner"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        public AttachedSigner(IKeySet keySet) : base(keySet)
        {
            _signer = new AttachedSignerHelper(keySet);

        }

        /// <summary>
        /// Signs the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <param name="hidden">The hidden data used to generate the digest signature.</param>
        /// <returns></returns>
        public WebBase64 Sign(String rawData,Byte[] hidden =null)
        {
            return WebBase64.FromBytes(Sign(RawStringEncoding.GetBytes(rawData), hidden));

        }


        /// <summary>
        /// Signs the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="hidden">The hidden data used to generate the digest signature.</param>
        /// <returns></returns>
        public byte[] Sign(byte[] data, Byte[] hidden =null)
        {
            using (var outstream = new MemoryStream())
            using (var memstream = new MemoryStream(data))
            {
                Sign(memstream,outstream, hidden);
                outstream.Flush();
                return outstream.ToArray();
            }
        }

        /// <summary>
        /// Signs the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="signedData">The stream to write the data with attached signature.</param>
        /// <param name="hidden">The hidden data that can be used to generate the signature.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        public void Sign(Stream input, Stream signedData, Byte[] hidden =null, long inputLength =-1)
        {
            _signer.Sign(input, signedData, hidden, inputLength);
        }

        /// <summary>
        /// Helper subclass to sign correctly
        /// </summary>
        protected class AttachedSignerHelper:Signer
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="AttachedSignerHelper"/> class.
            /// </summary>
            /// <param name="keySet">The key set.</param>
            public AttachedSignerHelper(IKeySet keySet)
                : base(keySet)
            {
                
            }

            /// <summary>
            /// Signs the specified data.
            /// </summary>
            /// <param name="input">The input.</param>
            /// <param name="signedData">The signed data.</param>
            /// <param name="hidden">The hidden data used to generate the digest signature.</param>
            /// <param name="inputLength">(optional) Length of the input.</param>
            /// <exception cref="System.ArgumentException">Stream must be able to seek.;data</exception>
            /// <exception cref="System.ArgumentException">Stream must be able to seek.;data</exception>
            public void Sign(Stream input, Stream signedData, Byte[] hidden, long inputLength)
            {
                if (!input.CanSeek)
                {
                    throw new ArgumentException("Stream must be able to seek.", "data");
                }

                long position = input.Position;
                var fullLength = inputLength < 0 ? input.Length : inputLength + input.Position;

                if (Int32.MaxValue < fullLength - position)
                {
                    throw new ArgumentException("Data is too large to attach signature.", "data");
                }

                base.Sign(input, signedData, prefixData: null, postfixData: hidden, signatureData: Tuple.Create(fullLength, position, input), inputLength: inputLength);
            }



            /// <summary>
            /// Postfixes the data then signs it.
            /// </summary>
            /// <param name="signingStream">The signing stream.</param>
            /// <param name="extra">The extra data passed by postfixData.</param>
            protected override void PostfixDataSign(Crypto.Streams.HashingStream signingStream, object extra)
            {
                var bytes = extra as byte[] ?? new byte[0];
           
                    var len = Utility.GetBytes(bytes.Length);
                    signingStream.Write(len, 0, len.Length);
                    signingStream.Write(bytes,0, bytes.Length);

                base.PostfixDataSign(signingStream, extra:null);
            }

            /// <summary>
            /// Pads the signature with extra data.
            /// </summary>
            /// <param name="signature">The signature.</param>
            /// <param name="outputStream">The padded signature.</param>
            /// <param name="extra">The extra data passed by sigData.</param>
            protected override void PadSignature(byte[] signature, Stream outputStream, object extra)
            {
                var padData = (Tuple<long, long, Stream>)extra; 
                var stopLength = padData.Item1;
                var position = padData.Item2;
                var input = padData.Item3;

                var key = GetPrimaryKey() as ISignerKey;
                outputStream.Write(FormatBytes, 0, FormatBytes.Length);
                outputStream.Write(key.GetKeyHash(), 0, KeyHashLength);

                var lengthBytes = Utility.GetBytes((int)(stopLength - position));
                outputStream.Write(lengthBytes, 0, lengthBytes.Length);
                padData.Item3.Seek(position, SeekOrigin.Begin);
                using (var reader = new NondestructiveBinaryReader(input))
                {
                    var adjustedBufferSize = (int)Math.Min(BufferSize, (stopLength - input.Position));
                    while (reader.Peek() != -1 && input.Position < stopLength)
                    {
                        byte[] buffer = reader.ReadBytes(adjustedBufferSize);
                        outputStream.Write(buffer, 0, buffer.Length);
                    }
                }
                outputStream.Write(signature, 0, signature.Length);
            }
        }
    }
}

