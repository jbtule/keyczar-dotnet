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
using System.Security.Cryptography;
using Keyczar.Util;

namespace Keyczar.Crypto.Streams
{
    /// <summary>
    /// standard microsoft targeted symmetric encryption wrapper
    /// </summary>
    public class DotNetSymmetricStream : FinishingStream
    {

        /// <summary>
        /// Gets the length of the tag.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <returns></returns>
        public override int GetTagLength(byte[] header)
        {
            return _tagSize;
        }

        private SymmetricAlgorithm _alg;
        private readonly bool _encrypt;
        private CryptoStream _output;
        private Stream _rawOutput;
        private readonly int _tagSize;
        private ICryptoTransform _transform;
        private bool _init = false;
        /// <summary>
        /// Initializes a new instance of the <see cref="DotNetSymmetricStream"/> class.
        /// </summary>
        /// <param name="alg">The alg.</param>
        /// <param name="output">The output.</param>
        /// <param name="tagSize">Size of the tag.</param>
        /// <param name="encrypt">if set to <c>true</c> [encrypt].</param>
        public DotNetSymmetricStream(SymmetricAlgorithm alg, Stream output, int tagSize, bool encrypt)
        {
            _alg = alg;
            _encrypt = encrypt;
                
            _rawOutput = output;
            _tagSize = tagSize;
        }

        private CryptoStream Output
        {
            get
            {
                if ( _output == null)
                {
                    _transform = _encrypt ? _alg.CreateEncryptor() : _alg.CreateDecryptor();
                    _output =new NonDestructiveCryptoStream(_rawOutput, _transform, CryptoStreamMode.Write);
                }
                return _output;
            }
        }


        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            if (_output !=null)
                _output.Dispose();
            _output = null;
            _rawOutput = null;
            if(_transform !=null)
                _transform.Dispose();
            _transform = null; 
            if(disposing)
            {
                //_alg.Dispose();

            }
            _alg = null;
      
        }

        /// <summary>
        /// When overridden in a derived class, clears all buffers for this stream and causes any buffered data to be written to the underlying device.
        /// </summary>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        public override void Flush()
        {
            Output.Flush();
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
            if(!_init)
            {
                if (_encrypt)
                {
                    _rawOutput.Write(_alg.IV, 0, _alg.IV.Length);

                }else
                {
                    var iv = new byte[_alg.BlockSize/8];
                    Array.Copy(buffer,0,iv, 0, iv.Length);
                    _alg.IV = iv;
                    offset = offset + iv.Length;
                    count = count - iv.Length;
                }
                _init = true;
            }
            Output.Write(buffer, offset, count);
        }

        /// <summary>
        /// Finishes this instance.
        /// </summary>
        public override void Finish()
        {
            if (!_init && _encrypt)
            {
                _rawOutput.Write(_alg.IV, 0, _alg.IV.Length);
                _init = true;
            }
            Output.FlushFinalBlock();
        }
    }
}