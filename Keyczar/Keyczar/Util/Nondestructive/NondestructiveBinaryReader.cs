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

namespace Keyczar.Util
{
    /// <summary>
    /// Reader that won't close the stream when disposed
    /// </summary>
    public class NondestructiveBinaryReader : BinaryReader
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NondestructiveBinaryReader"/> class.
        /// </summary>
        /// <param name="input">The input.</param>
        public NondestructiveBinaryReader(Stream input) : base(input)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NondestructiveBinaryReader"/> class.
        /// </summary>
        /// <param name="input">The supplied stream.</param>
        /// <param name="encoding">The character encoding.</param>
        /// <exception cref="T:System.ArgumentException">The stream does not support reading, the stream is null, or the stream is already closed. </exception>
        /// <exception cref="T:System.ArgumentNullException">
        /// 	<paramref name="encoding"/> is null. </exception>
        public NondestructiveBinaryReader(Stream input, Encoding encoding) : base(input, encoding)
        {
        }

        /// <summary>
        /// Peeks this positions byte.
        /// </summary>
        /// <returns></returns>
        public int Peek()
        {
            if (BaseStream == null)
            {
                return -1;
            }
            var position = BaseStream.Position;
            var num = BaseStream.ReadByte();
            BaseStream.Position = position;
            return num;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.BinaryReader"/> class and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(false);
        }
    }
}