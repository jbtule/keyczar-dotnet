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
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Wrapper for AEAD symmetric block ciphers  using bouncy castle
    /// </summary>
    public class SymmetricAeadStream : FinishingStream
    {
        private IAeadBlockCipher _cipher;
        private readonly int _tagLength;
        private Action<byte[], IAeadBlockCipher, byte[], bool> _initFunc;
        private readonly bool _encrypt;
        private Stream _output;
        private byte[] _nonce;
        private byte[] _header;
        private bool _init = false;
        private int _outLen = 0;
        private int _inLen = 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricAeadStream"/> class.
        /// </summary>
        /// <param name="makeCipher">The make cipher.</param>
        /// <param name="outStream">The out stream.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="tagLength">Length of the tag.</param>
        /// <param name="initFunc">The init func.</param>
        /// <param name="encrypt">if set to <c>true</c> [encrypt].</param>
        public SymmetricAeadStream(Func<IAeadBlockCipher> makeCipher,
                                   Stream outStream,
                                   byte[] nonce,
                                   int tagLength,
                                   Action<byte[], IAeadBlockCipher, byte[], bool> initFunc,
                                   bool encrypt)
        {
            _output = outStream;
            _nonce = nonce;

            _tagLength = tagLength;
            _initFunc = initFunc;
            _encrypt = encrypt;
            _cipher = makeCipher();
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            Flush();
            Secure.Clear(_nonce);
            _nonce = null;
            Secure.Clear(_header);
            _header = null;
            //_cipher.Reset();
            _cipher = null;
            _initFunc = null;
            _output = null;
            _outLen = 0;
            _init = false;
            _inLen = 0;
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
                if (_encrypt)
                {
                    _output.Write(_nonce, 0, _nonce.Length);
                }
                else
                {
                    Array.Copy(buffer, 0, _nonce, 0, _nonce.Length);

                    offset = offset + _nonce.Length;
                    count = count - _nonce.Length;
                }
                _initFunc(_nonce, _cipher, _header, _encrypt);
                _init = true;
            }

            var outBuffer = new byte[_cipher.GetUpdateOutputSize(count)];
            var outLen = _cipher.ProcessBytes(buffer, offset, count, outBuffer, 0);
            _output.Write(outBuffer, 0, outLen);
            Secure.Clear(outBuffer);
            _outLen += outLen;
            _inLen += count;
        }

        /// <summary>
        /// Gets the length of the tag.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns>0 because it's done as part of the encryption &amp; decryption</returns>
        public override int GetTagLength(byte[] header)
        {
            _header = header;

            return 0; //Because the alortihm includes it.
        }

        /// <summary>
        /// Finishes this instance.
        /// </summary>
        /// <exception cref="InvalidCryptoDataException"></exception>
        public override void Finish()
        {
            try
            {
                if (!_init && _encrypt)
                {
                    _output.Write(_nonce, 0, _nonce.Length);
                    _initFunc(_nonce, _cipher, _header, _encrypt);
                    _init = true;
                }

                var buffLen = _cipher.GetOutputSize(_inLen) - _outLen;
                var buffer = new byte[buffLen];
                var writeLen = _cipher.DoFinal(buffer, 0);
                _output.Write(buffer, 0, writeLen);
                Secure.Clear(buffer);
            }
            catch (InvalidCipherTextException ex)
            {
                throw new InvalidCryptoDataException(ex.Message);
            }
        }
    }
}