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
    /// Bouncy Castle Asymmetric encryption
    /// </summary>
    public class AsymmetricStream : FinishingStream
    {
        private IBufferedCipher _cipher;
        private Stream _output;
        private readonly Action<IBufferedCipher, bool> _initFunc;
        private readonly bool _encrypt;

        private int _outLen;
        private int _inLen;
        private bool _init;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricStream"/> class.
        /// </summary>
        /// <param name="cipher">The cipher.</param>
        /// <param name="output">The output.</param>
        /// <param name="initFunc">The init func.</param>
        /// <param name="encrypt">if set to <c>true</c> [encrypt].</param>
        public AsymmetricStream(IAsymmetricBlockCipher cipher, Stream output, Action<IBufferedCipher, bool> initFunc,
                                bool encrypt)
        {
            _cipher = new BufferedAsymmetricBlockCipher(cipher);
            _output = output;
            _initFunc = initFunc;
            _encrypt = encrypt;
        }

        private void Init()
        {
            if (!_init)
            {
                _initFunc(_cipher, _encrypt);
                _init = true;
            }
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
            }
            _cipher.Reset();
            _cipher = null;
            _output.Flush();
            _output = null;
            base.Dispose(disposing);
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
        /// When overridden in a derived class, writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
        /// </summary>
        /// <param name="buffer">An array of bytes. This method copies <paramref name="count" /> bytes from <paramref name="buffer" /> to the current stream.</param>
        /// <param name="offset">The zero-based byte offset in <paramref name="buffer" /> at which to begin copying bytes to the current stream.</param>
        /// <param name="count">The number of bytes to be written to the current stream.</param>
        /// <exception cref="InvalidCryptoDataException"></exception>
        /// <exception cref="T:System.ArgumentException">The sum of <paramref name="offset" /> and <paramref name="count" /> is greater than the buffer length.</exception>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="buffer" /> is null.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException"><paramref name="offset" /> or <paramref name="count" /> is negative.</exception>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs.</exception>
        /// <exception cref="T:System.NotSupportedException">The stream does not support writing.</exception>
        /// <exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed.</exception>
        public override void Write(byte[] buffer, int offset, int count)
        {
            try
            {
                Init();
                var outBuffer = new byte[_cipher.GetUpdateOutputSize(count)];
                var outLen = _cipher.ProcessBytes(buffer, offset, count, outBuffer, 0);
                _output.Write(outBuffer, 0, outLen);
                outBuffer.Clear();
                _outLen += outLen;
                _inLen += count;
            }
            catch (InvalidCipherTextException ex)
            {
                throw new InvalidCryptoDataException(ex.Message);
            }
        }

        /// <summary>
        /// Gets the length of the tag.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns></returns>
        public override int GetTagLength(byte[] header)
        {
            return 0;
        }

        /// <summary>
        /// Finishes this instance.
        /// </summary>
        /// <exception cref="InvalidCryptoDataException"></exception>
        public override void Finish()
        {
            try
            {
                Init();
                var buffLen = _cipher.GetOutputSize(_inLen) - _outLen;
                var buffer = new byte[buffLen];
                var writeLen = _cipher.DoFinal(buffer, 0);
                _output.Write(buffer, 0, writeLen);
                buffer.Clear();
            }
            catch (InvalidCipherTextException ex)
            {
                throw new InvalidCryptoDataException(ex.Message);
            }
        }
    }
}