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
using Keyczar.Util;
using Org.BouncyCastle.Crypto.Macs;

namespace Keyczar.Crypto.Streams
{
    /// <summary>
    /// 
    /// </summary>
    public class HmacStream : VerifyingStream
    {
        /// <summary>
        /// Gets the length of the tag.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns></returns>
        public override int GetTagLength(byte[] header)
        {
            return _hmacAlg.GetMacSize();
        }

        private HMac _hmacAlg;

        /// <summary>
        /// Initializes a new instance of the <see cref="HmacStream"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public HmacStream(HMac algorithm)
        {
            _hmacAlg = algorithm;
            _hashValue = new byte[(_hmacAlg.GetMacSize())];
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            Finish();

            if (disposing)
            {
                _hmacAlg.Reset();
            }
            _hmacAlg = null;

            base.Dispose(disposing);
        }

        /// <summary>
        /// When overridden in a derived class, clears all buffers for this stream and causes any buffered data to be written to the underlying device.
        /// </summary>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        public override void Flush()
        {
        }

        /// <summary>
        /// When overridden in a derived class, writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
        /// </summary>
        /// <param name="buffer">An array of bytes. This method copies <paramref name="count"/> bytes from <paramref name="buffer"/> to the current stream.</param>
        /// <param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin copying bytes to the current stream.</param>
        /// <param name="count">The number of bytes to be written to the current stream.</param>
        /// <exception cref="T:System.ArgumentException">The sum of <paramref name="offset"/> and <paramref name="count"/> is greater than the buffer length. </exception>
        /// <exception cref="T:System.ArgumentNullException">
        /// 	<paramref name="buffer"/> is null. </exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException">
        /// 	<paramref name="offset"/> or <paramref name="count"/> is negative. </exception>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        /// <exception cref="T:System.NotSupportedException">The stream does not support writing. </exception>
        /// <exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed. </exception>
        public override void Write(byte[] buffer, int offset, int count)
        {
            _hmacAlg.BlockUpdate(buffer, offset, count);
        }

        private byte[] _hashValue;
        private bool _final;

        /// <summary>
        /// Gets the hash value.
        /// </summary>
        /// <value>The hash value.</value>
        public override byte[] HashValue
        {
            get { return (byte[]) _hashValue.Clone(); }
        }


        /// <summary>
        /// Finishes this instance.
        /// </summary>
        public override void Finish()
        {
            if (!_final)
            {
                _hmacAlg.DoFinal(_hashValue, 0);

                _final = true;
            }
        }

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        public override bool VerifySignature(byte[] signature)
        {
            Finish();
            return Secure.Equals(signature, HashValue, maxCount: _hmacAlg.GetMacSize());
        }
    }
}