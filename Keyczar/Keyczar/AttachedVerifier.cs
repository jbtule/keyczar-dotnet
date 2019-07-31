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
    public class AttachedVerifier:KeyczarBase
    {
        private HelperAttachedVerify _verifier;

        /// <summary>
        /// Initializes a new instance of the <see cref="AttachedSigner"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public AttachedVerifier(string keySetLocation)
            : this(new FileSystemKeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AttachedSigner" /> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <exception cref="InvalidKeySetException">This key set can not be used for verifying signatures.</exception>
        public AttachedVerifier(IKeySet keySet) : base(keySet)
        {
            if (keySet.Metadata.Purpose != KeyPurpose.Verify
                && keySet.Metadata.Purpose != KeyPurpose.SignAndVerify)
            {
                throw new InvalidKeySetException("This key set can not be used for verifying signatures.");
            }
            _verifier = new HelperAttachedVerify(keySet, this);
        }


        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="hidden">Optional hidden data used to generate the digest signature.</param>
        /// <returns></returns>
        public bool Verify(WebBase64 signedMessage, byte[] hidden =null) =>
            Verify(signedMessage.ToBytes(), hidden);

        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="hidden">Optional hidden data used to generate the digest signature.</param>
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
        /// <param name="input">The input.</param>
        /// <param name="hidden">Optional hidden data used to generate the digest signature.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <returns></returns>
        public bool Verify(Stream input, byte[] hidden =null, long inputLength=-1)
            => _verifier.VerifyHidden(input, null, hidden, inputLength);


        /// <summary>
        /// Gets Verified message from signed message
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <param name="hidden">Optional hidden data used to generate the digest signature.</param>
        /// <returns></returns>
        /// <exception cref="InvalidCryptoDataException">Data Doesn't Match Signature!</exception>
         public string VerifiedMessage(WebBase64 rawData, byte[] hidden = null) 
            => Config.RawStringEncoding.GetString(VerifiedMessage(rawData.ToBytes(), hidden));


        /// <summary>
         /// Gets Verified message from signed message
         /// </summary>
         /// <param name="data">The data.</param>
         /// <param name="hidden">Optional hidden data used to generate the digest signature.</param>
         /// <returns></returns>
         /// <exception cref="InvalidCryptoDataException">Data Doesn't Match Signature!</exception>
        public byte[] VerifiedMessage(byte[] data, byte[] hidden = null)
        {
            using (var output = new MemoryStream())
            using (var memstream = new MemoryStream(data))
            {
                VerifiedMessage(memstream,output, hidden);
                return output.ToArray();
            }
        }

        /// <summary>
        /// Gets Verified message from signed message
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="verifiedMessage">The output message.</param>
        /// <param name="hidden">The hidden.</param>
        /// <param name="inputLength">Length of the input.</param>
        /// <exception cref="InvalidCryptoDataException">Data Doesn't Match Signature!</exception>
        public void VerifiedMessage(Stream input, Stream verifiedMessage, byte[] hidden = null, long inputLength=-1)
        {
            if (!TryGetVerifiedMessage(input, verifiedMessage, hidden, inputLength))
            {
                throw new InvalidCryptoDataException("Data Doesn't Match Signature!");
            }
        }

        /// <summary>
        /// Tries to get the verified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="verifiedMessage">The verified message.</param>
        /// <param name="hidden">The hidden.</param>
        /// <returns>false if signature is not correct</returns>
        public bool TryGetVerifiedMessage(WebBase64 signedMessage, out string verifiedMessage, byte[] hidden = null)
        {
            byte[] output;
            var verified = TryGetVerifiedMessage(signedMessage.ToBytes(), out output, hidden);
            verifiedMessage = Config.RawStringEncoding.GetString(output);
            return verified;
        }

        /// <summary>
        /// Tries to get the verified message.
        /// </summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="verifiedMessage">The verified message.</param>
        /// <param name="hidden">The hidden.</param>
        /// <returns>false if signature is not correct</returns>
        public bool TryGetVerifiedMessage(byte[] signedMessage, out byte[] verifiedMessage, byte[] hidden = null)
        {
            try
            {
                using (var output = new MemoryStream())
                using (var memstream = new MemoryStream(signedMessage))
                {
                    var verified = TryGetVerifiedMessage(memstream, output, hidden);
                    verifiedMessage = output.ToArray();
                    return verified;
                }
            }
            catch (InvalidCryptoDataException)
            {
                verifiedMessage = null;
                return false;
            }
        }

        /// <summary>
        /// Tries to get the verified message.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="verifiedMessage">The verified message.</param>
        /// <param name="hiddden">The hiddden.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <returns>
        /// false if signature is not correct
        /// </returns>
        public bool TryGetVerifiedMessage(Stream input, Stream verifiedMessage, byte[] hiddden = null, long inputLength=-1) 
            => _verifier.VerifyHidden(input, verifiedMessage, hiddden, inputLength);

        /// <summary>
        /// Does the attache verify work.
        /// </summary>
        protected class HelperAttachedVerify:Verifier
        {
            private KeyczarBase _parent;
            private KeyczarConfig _config1;

            /// <summary>
            /// Initializes a new instance of the <see cref="HelperAttachedVerify"/> class.
            /// </summary>
            /// <param name="keySet">The key set.</param>
            public HelperAttachedVerify(IKeySet keySet, KeyczarBase parent) : base(keySet)
            {
                _parent = parent;
            }

            public override KeyczarConfig Config
            {
                get => _config1 ?? _parent.Config;
                set => _config1 = value;
            }

            /// <summary>
            /// Verifies the specified signed message.
            /// </summary>
            /// <param name="input">The signed message.</param>
            /// <param name="verifiedMessage">The verified message.</param>
            /// <param name="hidden">The hidden data used to generate the digest signature.</param>
            /// <param name="inputLength">(optional) Length of the input.</param>
            /// <returns></returns>
            /// <exception cref="InvalidCryptoDataException">Data doesn't appear to have signatures attached!</exception>
            [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
            public bool VerifyHidden(Stream input, Stream verifiedMessage, byte[] hidden, long inputLength)
            {
                var fullLength = inputLength < 0 ? input.Length : inputLength + input.Position;
                using (var reader = new NondestructiveBinaryReader(input))
                {
                    var header = reader.ReadBytes(KeyczarConst.HeaderLength);
                    var length = Utility.ToInt32(reader.ReadBytes(4));

                    if (fullLength < input.Position + length)
                    {
                        throw new InvalidCryptoDataException("Data doesn't appear to have signatures attached!");
                    }

                    using(var sigStream = new MemoryStream())
                    {
                        using (Utility.ResetStreamWhenFinished(input))
                        {
                            sigStream.Write(header, 0, header.Length);
                            input.Seek(length, SeekOrigin.Current);
                            while (reader.Peek() != -1 && input.Position < fullLength)
                            {
                                var adjustedBufferSize = (int)Math.Min(BufferSize, (fullLength - input.Position));
                                var buffer = reader.ReadBytes(adjustedBufferSize);
                                sigStream.Write(buffer, 0, buffer.Length);
                            } 
                            sigStream.Flush();
                        }
                        using (var signedMessageLimtedLength = new NondestructivePositionLengthLimitingStream(input))
                        {
                            signedMessageLimtedLength.SetLength(length);
                            if (verifiedMessage != null)
                            {
                                using (Utility.ResetStreamWhenFinished(input))
                                {
                                    signedMessageLimtedLength.CopyTo(verifiedMessage);
                                }
                            }
                            var verified= Verify(signedMessageLimtedLength, sigStream.ToArray(), prefixData: null, postfixData: hidden, inputLength: inputLength);
                            input.Seek(fullLength, SeekOrigin.Begin);
                            return verified;
                        }
                    }
                }
            }

            /// <summary>
            /// Postfixes data before verifying.
            /// </summary>
            /// <param name="verifyingStream">The verifying stream.</param>
            /// <param name="extra">The extra data passed by postFixData</param>
            protected override void PostfixDataVerify(Crypto.Streams.VerifyingStream verifyingStream, object extra)
            {
                var bytes = extra as byte[] ?? new byte[0];

                var len = Utility.GetBytes(bytes.Length);
                verifyingStream.Write(len, 0, len.Length);
                verifyingStream.Write(bytes, 0, bytes.Length);

                base.PostfixDataVerify(verifyingStream, extra: null);
            }
        }
    }
}

