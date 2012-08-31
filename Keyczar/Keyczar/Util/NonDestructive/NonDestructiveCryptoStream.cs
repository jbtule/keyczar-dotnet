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
using System.Security.Cryptography;
using System.Text;

namespace Keyczar.Util
{
    /// <summary>
    /// Crypto Stream that doesn't close the underlying stream when disposed
    /// </summary>
    public class NonDestructiveCryptoStream:CryptoStream
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NonDestructiveCryptoStream"/> class.
        /// </summary>
        /// <param name="stream">The stream on which to perform the cryptographic transformation.</param>
        /// <param name="transform">The cryptographic transformation that is to be performed on the stream.</param>
        /// <param name="mode">One of the <see cref="T:System.Security.Cryptography.CryptoStreamMode"/> values.</param>
        /// <exception cref="T:System.ArgumentException">
        /// 	<paramref name="stream"/> is not readable.</exception>
        /// <exception cref="T:System.ArgumentException">
        /// 	<paramref name="stream"/> is not writable.</exception>
        /// <exception cref="T:System.ArgumentException">
        /// 	<paramref name="stream"/> is invalid.</exception>
        public NonDestructiveCryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode) : base(stream, transform, mode)
        {
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.Security.Cryptography.CryptoStream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(false);
        }
    }
}
