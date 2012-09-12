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
        /// <param name="message">The message.</param>
        /// <param name="hidden">The hidden data used to generate the digest signature.</param>
        /// <returns></returns>
		public string Sign(String message,Byte[] hidden =null)
		{
		    return new String(WebSafeBase64.Encode(Sign(DefaultEncoding.GetBytes(message), hidden)));

		}


        /// <summary>
        /// Signs the specified raw data.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="hidden">The hidden data used to generate the digest signature.</param>
        /// <returns></returns>
		public byte[] Sign(byte[] message, Byte[] hidden =null)
		{
            using (var outstream = new MemoryStream())
            using (var memstream = new MemoryStream(message))
            {
                Sign(memstream,outstream, hidden);
                outstream.Flush();
                return outstream.ToArray();
            }
		}

        /// <summary>
        /// Signs the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="signedData">The stream to write the data with attached signature.</param>
        /// <param name="hidden">The hidden data that can be used to generate the signature.</param>
		public void Sign(Stream data, Stream signedData, Byte[] hidden =null)
		{
		    _signer.Sign(data, signedData, hidden);
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
            /// <param name="data">The data.</param>
            /// <param name="signedData">The signed data.</param>
            /// <param name="hidden">The hidden data used to generate the digest signature.</param>
            public void Sign(Stream data, Stream signedData, Byte[] hidden = null)
            {
                if(!data.CanSeek)
                {
                    throw new ArgumentException("Stream must be able to seek.", "data");
                }

                long position = data.Position;
                long fulllength = data.Length;

                if (Int32.MaxValue < fulllength - position)
                {
                    throw new ArgumentException("Data is to large to attach signature", "data");
                }

                base.Sign(data, signedData, prefixData: null, postfixData: hidden, sigData: Tuple.Create(fulllength,position,data));
            }



            /// <summary>
            /// Postfixes the data then signs it.
            /// </summary>
            /// <param name="signingStream">The signing stream.</param>
            /// <param name="extra">The extra data passed by postfixData.</param>
            protected override void PostfixData(Crypto.Streams.HashingStream signingStream, object extra)
            {
                var bytes = extra as byte[] ?? new byte[0];
           
                    var len = Utility.GetBytes(bytes.Length);
                    signingStream.Write(len, 0, len.Length);
                    signingStream.Write(bytes,0, bytes.Length);

                base.PostfixData(signingStream, extra:null);
            }

            /// <summary>
            /// Pads the signature with extra data.
            /// </summary>
            /// <param name="signature">The signature.</param>
            /// <param name="outstream">The padded signature.</param>
            /// <param name="extra">The extra data passed by sigData.</param>
            protected override void PadSignature(byte[] signature, Stream outstream, object extra)
            {
                var padData = (Tuple<long, long, Stream>) extra;
                var key = GetPrimaryKey() as ISignerKey;
                outstream.Write(FORMAT_BYTES, 0, FORMAT_BYTES.Length);
                outstream.Write(key.GetKeyHash(), 0, KEY_HASH_LENGTH);
                var lengthBytes = Utility.GetBytes((int) (padData.Item1 - padData.Item2));
                outstream.Write(lengthBytes, 0, lengthBytes.Length);
                padData.Item3.Seek(padData.Item2, SeekOrigin.Begin);
                using (var reader = new NonDestructiveBinaryReader(padData.Item3))
                {
                    while (reader.Peek() != -1)
                    {
                        byte[] buffer = reader.ReadBytes(BUFFER_SIZE);
                        outstream.Write(buffer, 0, buffer.Length);
                    }
                }
                outstream.Write(signature, 0, signature.Length);
            }
		}
	}
}

