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
using Keyczar.Crypto.Streams;
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Verifies signatures with an expiration date &amp; time
    /// </summary>
    public class TimeoutVerifier:Keyczar
    {
        /// <summary>
        /// Binary length of expiration in signature
        /// </summary>
        public readonly static int TimeoutLength = 8;

        /// <summary>
        /// Gets binary format of the date time.
        /// </summary>
        /// <param name="date">The date.</param>
        /// <returns></returns>
        protected static long FromDateTime(DateTime date)
        {
            return (long)((date.ToUniversalTime() - new DateTime(1970, 1, 1).ToUniversalTime()).TotalMilliseconds);
        }

        private Verifier _verifier;

        /// <summary>
        /// Initializes a new instance of the <see cref="TimeoutVerifier"/> class.
        /// </summary>
        /// <param name="keysetLocation">The keyset location.</param>
        public TimeoutVerifier(string keysetLocation) : this(new KeySet(keysetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimeoutVerifier"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        public TimeoutVerifier(IKeySet keySet) : base(keySet)
        {
            _verifier = new TimeoutVerifierHelper(keySet);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        public override void Dispose()
        {
            _verifier = _verifier.SafeDispose(); 
            base.Dispose();
        }

        /// <summary>
        /// Verifies the specified raw data.
        /// </summary>
        /// <param name="rawData">The raw data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        public bool Verify(string rawData, string signature)
        {
            var decodedSignature = WebSafeBase64.Decode(signature.ToCharArray());

            return Verify(DefaultEncoding.GetBytes(rawData), decodedSignature);
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
        /// Verifies the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        public bool Verify(Stream data, byte[] signature)
        {
            var milliseconds = FromDateTime(DateTime.Now);

            if(!_verifier.Verify(data, signature))
                return false; 
            using(var stream = new MemoryStream(signature))
            using (var reader = new NonDestructiveBinaryReader(stream))
            {
                reader.ReadBytes(HEADER_LENGTH);
                var expiration =reader.ReadBytes(TimeoutLength);
                var expMilliseconds = Utility.ToInt64(expiration);
                return milliseconds < expMilliseconds;
            }
        }

        /// <summary>
        /// Helper class to verify the expiration date with the data
        /// </summary>
        protected class TimeoutVerifierHelper:Verifier
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="TimeoutVerifierHelper"/> class.
            /// </summary>
            /// <param name="keySetLocation">The key set location.</param>
            public TimeoutVerifierHelper(string keySetLocation)
                : this(new KeySet(keySetLocation))
            {
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="TimeoutVerifierHelper"/> class.
            /// </summary>
            /// <param name="keySet">The key set.</param>
            public TimeoutVerifierHelper(IKeySet keySet) : base(keySet)
            {
            }

            /// <summary>
            /// Verifies the specified data.
            /// </summary>
            /// <param name="data">The data.</param>
            /// <param name="signature">The signature.</param>
            /// <param name="prefixData">The prefix data.</param>
            /// <param name="postfixData">The post fix data.</param>
            /// <returns></returns>
            protected override bool Verify(Stream data, byte[] signature, object prefixData, object postfixData)
            {
                var newsig = new byte[signature.Length - TimeoutLength];
                Array.Copy(signature,0,newsig,0,HEADER_LENGTH);
                Array.Copy(signature,HEADER_LENGTH+TimeoutLength,newsig,HEADER_LENGTH,newsig.Length - HEADER_LENGTH);
                var expireBytes = new byte[TimeoutLength];
                Array.Copy(signature,HEADER_LENGTH, expireBytes,0,TimeoutLength);

                return base.Verify(data, newsig, expireBytes, postfixData);
            }


            /// <summary>
            /// Prefixes the data before verifying.
            /// </summary>
            /// <param name="verifyingStream">The verifying stream.</param>
            /// <param name="extra">The extra data passed by prefixData</param>
            protected override void PrefixData(VerifyingStream verifyingStream, object extra)
            {
                base.PrefixData(verifyingStream, null);
                var timeout = (byte[]) extra;
                verifyingStream.Write(timeout, 0, timeout.Length);
            }
          
        }
    }
}
