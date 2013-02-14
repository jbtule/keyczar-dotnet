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
            return (long)((date.ToUniversalTime() - new DateTime(1970, 1, 1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds);
        }

        private Verifier _verifier;
        private Func<DateTime> _currentDateTime;

        /// <summary>
        /// Initializes a new instance of the <see cref="TimeoutVerifier" /> class.
        /// </summary>
        /// <param name="keySetLocation">The keyset location.</param>
        /// <param name="currentDateTime">The current date time providers.</param>
        public TimeoutVerifier(string keySetLocation, Func<DateTime> currentDateTime = null)
            : this(new KeySet(keySetLocation), currentDateTime)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimeoutVerifier" /> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <param name="currentDateTime">The current date time provider.</param>
        public TimeoutVerifier(IKeySet keySet, Func<DateTime> currentDateTime = null)
            : base(keySet)
        {
            _verifier = new TimeoutVerifierHelper(keySet);
            _currentDateTime = currentDateTime ?? (()=> DateTime.Now);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = "_verifier")]
        protected override void Dispose(bool disposing)
        {
            _verifier = _verifier.SafeDispose();
            base.Dispose(disposing);
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
        /// Verifies the specified data.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="inputLength">(optional) Length of the input.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
        public bool Verify(Stream input, byte[] signature, long inputLength = -1)
        {
            

            var milliseconds = FromDateTime(_currentDateTime());
            
            if (!_verifier.Verify(input, signature, inputLength))
                return false; 
            using(var stream = new MemoryStream(signature))
            using (var reader = new NondestructiveBinaryReader(stream))
            {
                reader.ReadBytes(HeaderLength);
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
            /// <param name="input">The input.</param>
            /// <param name="signature">The signature.</param>
            /// <param name="prefixData">The prefix data.</param>
            /// <param name="postfixData">The post fix data.</param>
            /// <param name="inputLength">(optional) Length of the input.</param>
            /// <returns></returns>
            protected override bool Verify(Stream input, byte[] signature, object prefixData, object postfixData, long inputLength)
            {
                var newsig = new byte[signature.Length - TimeoutLength];
                Array.Copy(signature,0,newsig,0,HeaderLength);
                Array.Copy(signature,HeaderLength+TimeoutLength,newsig,HeaderLength,newsig.Length - HeaderLength);
                var expireBytes = new byte[TimeoutLength];
                Array.Copy(signature,HeaderLength, expireBytes,0,TimeoutLength);

                return base.Verify(input, newsig, expireBytes, postfixData, inputLength);
            }


            /// <summary>
            /// Prefixes the data before verifying.
            /// </summary>
            /// <param name="verifyingStream">The verifying stream.</param>
            /// <param name="extra">The extra data passed by prefixData</param>
            protected override void PrefixDataVerify(VerifyingStream verifyingStream, object extra)
            {
                base.PrefixDataVerify(verifyingStream, null);
                var timeout = (byte[]) extra;
                verifyingStream.Write(timeout, 0, timeout.Length);
            }
          
        }
    }
}
