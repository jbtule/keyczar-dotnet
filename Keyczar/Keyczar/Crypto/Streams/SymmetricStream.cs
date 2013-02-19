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
using Org.BouncyCastle.Crypto;

namespace Keyczar.Crypto.Streams
{
    /// <summary>
    /// Bouncy Castle target symmetric encryption wrapper
    /// </summary>
    public class SymmetricStream : CipherTextOnlyFinishingStream
    {
        private IBufferedCipher _cipher;
        private Stream _output;
        private byte[] _iv;
        private readonly int _tagSize;
        private Action<byte[], IBufferedCipher, bool> _initFunc;
        private readonly bool _encrypt;
        private bool _init = false;
        private int _outLen;
        private int _inLen;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricStream"/> class.
        /// </summary>
        /// <param name="cipher">The cipher.</param>
        /// <param name="output">The output.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="tagSize">Size of the tag.</param>
        /// <param name="initFunc">The init func.</param>
        /// <param name="encrypt">if set to <c>true</c> [encrypt].</param>
        public SymmetricStream(IBufferedCipher cipher, Stream output, byte[] iv, int tagSize,
                               Action<byte[], IBufferedCipher, bool> initFunc, bool encrypt)
        {
            _cipher = cipher;
            _output = output;
            _iv = iv;
            _tagSize = tagSize;
            _initFunc = initFunc;
            _encrypt = encrypt;
        }


        /// <summary>
        /// When overridden in a derived class, clears all buffers for this stream and causes any buffered data to be written to the underlying device.
        /// </summary>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        public override void Flush()
        {
            _output.Flush();
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            Flush();
            _output = null;
            _iv = _iv.Clear();
            _initFunc = null;
            _cipher.Reset();
            _cipher = null;

            base.Dispose(disposing);
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
            if (!_init)
            {
                if (!CipherTextOnly)
                {
                    if (_encrypt)
                    {
                        _output.Write(_iv, 0, _iv.Length);
                    }
                    else
                    {
                        Array.Copy(buffer, 0, _iv, 0, _iv.Length);
                        offset = offset + _iv.Length;
                        count = count - _iv.Length;
                    }
                }
                _initFunc(_iv, _cipher, _encrypt);
                _init = true;
            }

            var outBuffer = new byte[_cipher.GetUpdateOutputSize(count)];
            var outLen = _cipher.ProcessBytes(buffer, offset, count, outBuffer, 0);
            _output.Write(outBuffer, 0, outLen);
            outBuffer.Clear();
            _outLen += outLen;
            _inLen += count;
        }

        /// <summary>
        /// Gets the length of the tag.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns></returns>
        public override int GetTagLength(byte[] header)
        {
            if (CipherTextOnly)
                return 0;
            return _tagSize;
        }

        /// <summary>
        /// Finishes this instance.
        /// </summary>
        public override void Finish()
        {
            if (!_init && _encrypt)
            {
                if (!CipherTextOnly)
                    _output.Write(_iv, 0, _iv.Length);

                _initFunc(_iv, _cipher, _encrypt);
                _init = true;
            }

            var buffLen = _cipher.GetOutputSize(_inLen) - _outLen;
            var buffer = new byte[buffLen];
            var writeLen = _cipher.DoFinal(buffer, 0);
            _output.Write(buffer, 0, writeLen);
            buffer.Clear();
        }

        /// <summary>
        /// Gets or sets a value indicating whether the output is  the [cipher text only].
        /// </summary>
        /// <value><c>true</c> if [cipher text only]; otherwise, <c>false</c>.</value>
        public override bool CipherTextOnly { get; set; }

        /// <summary>
        /// Gets or sets the IV.
        /// </summary>
        /// <value>The IV.</value>
        public override byte[] IV
        {
            get { return _iv; }
            set { _iv = value; }
        }
    }
}