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
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Verifies a message with an attached signature.
    /// </summary>
	public class AttachedVerifier:Keyczar
    {
        private HelperAttachedVerify _verifier;

		/// <summary>
		/// Initializes a new instance of the <see cref="AttachedSigner"/> class.
		/// </summary>
		/// <param name="keySetLocation">The key set location.</param>
		public AttachedVerifier(string keySetLocation)
			: base(keySetLocation)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="AttachedSigner"/> class.
		/// </summary>
		/// <param name="keySet">The key set.</param>
		public AttachedVerifier(IKeySet keySet) : base(keySet)
		{
			if (keySet.Metadata.Purpose != KeyPurpose.VERIFY
			    && keySet.Metadata.Purpose != KeyPurpose.SIGN_AND_VERIFY)
			{
				throw new InvalidKeyTypeException("This key set can not be used for verifying signatures.");
			}
            _verifier = new HelperAttachedVerify(keySet);
		}


        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="hidden">The hidden.</param>
        /// <returns></returns>
		public bool Verify(string signedMessage, byte[] hidden =null){

            return Verify(DefaultEncoding.GetBytes(signedMessage), hidden);
		}

        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="hidden">The hidden data used to generate the digest signature.</param>
        /// <returns></returns>
		public bool Verify(byte[] signedMessage, byte[] hidden =null){
            using (var memstream = new MemoryStream(signedMessage))
            {
                return Verify(memstream, hidden);
            }
		}

        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="hidden">The hidden data used to generate the digest signature.</param>
        /// <returns></returns>
		public bool Verify(Stream signedMessage, byte[] hidden =null)
        {
            return _verifier.Verify(signedMessage, hidden);
        }

        /// <summary>
        /// Does the attache verify work.
        /// </summary>
        protected class HelperAttachedVerify:Verifier
        {

            /// <summary>
            /// Initializes a new instance of the <see cref="HelperAttachedVerify"/> class.
            /// </summary>
            /// <param name="keySet">The key set.</param>
            public HelperAttachedVerify(IKeySet keySet) : base(keySet)
            {
            }

            /// <summary>
            /// Verifies the specified signed message.
            /// </summary>
            /// <param name="signedMessage">The signed message.</param>
            /// <param name="hidden">The hidden data used to generate the digest signature.</param>
            /// <returns></returns>
            public bool Verify(Stream signedMessage, byte[] hidden)
            {
        
                using (var reader = new NonDestructiveBinaryReader(signedMessage))
                {
                    var header = reader.ReadBytes(HEADER_LENGTH);
                    var length = Utility.ToInt32(reader.ReadBytes(4));
                    var position = signedMessage.Position;
                    signedMessage.Seek(length, SeekOrigin.Begin);
                    using(var sigStream = new MemoryStream())
                    {
                        sigStream.Write(header,0,header.Length);
                        while (reader.Peek() != -1)
                        {
                           var buffer = reader.ReadBytes(BUFFER_SIZE);
                           sigStream.Write(buffer, 0, buffer.Length);
                        } 
                        signedMessage.SetLength(position + length);
                        sigStream.Flush();
                        return Verify(signedMessage, sigStream.ToArray(), prefixData: null, postfixData: hidden);
                    }
                }
            }

            /// <summary>
            /// Postfixes data before verifying.
            /// </summary>
            /// <param name="verifyingStream">The verifying stream.</param>
            /// <param name="extra">The extra data passed by postFixData</param>
            protected override void PostfixData(Crypto.Streams.VerifyingStream verifyingStream, object extra)
            {
                var bytes = extra as byte[] ?? new byte[0];

                var len = Utility.GetBytes(bytes.Length);
                verifyingStream.Write(len, 0, len.Length);
                verifyingStream.Write(bytes, 0, bytes.Length);

                base.PostfixData(verifyingStream, extra: null);
            }
        }
	}
}

