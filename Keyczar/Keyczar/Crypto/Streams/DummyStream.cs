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


using Keyczar.Util;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;

namespace Keyczar.Crypto.Streams
{
    /// <summary>
    /// A Dummy Stream to fake verification if the key hash doesn't match
    /// </summary>
    public class DummyStream : HmacStream
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DummyStream" /> class.
        /// </summary>
        public DummyStream() : base(new HMac(new Sha1Digest()))
        {
        }

        /// <summary>
        /// Returns Blank Hash Value because this is a dummy operation
        /// </summary>
        /// <value>The blank shash value.</value>
        public override byte[] HashValue
        {
            get { return new byte[] {}; }
        }
    }
}