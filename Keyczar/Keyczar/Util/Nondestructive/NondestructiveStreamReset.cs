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

namespace Keyczar.Util
{
    /// <summary>
    /// Resets a stream when it's disposed or called reset
    /// </summary>
    public class NondestructiveStreamReset : IDisposable
    {
        private Stream _stream;
        private long _position;

        /// <summary>
        /// Initializes a new instance of the <see cref="NondestructiveStreamReset" /> class.
        /// </summary>
        /// <param name="stream">The stream.</param>
        public NondestructiveStreamReset(Stream stream)
        {
            _stream = stream;
            _position = stream.Position;
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="NondestructiveStreamReset" /> class.
        /// </summary>
        ~NondestructiveStreamReset()
        {
            Dispose(false);
        }

        /// <summary>
        /// Closes the current stream and releases any resources (such as sockets and file handles) associated with the current stream.
        /// </summary>
        public virtual void Close()
        {
            this.Dispose(false);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
                Reset();
            _stream = null;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Resets this Stream Position.
        /// </summary>
        public void Reset()
        {
            _stream.Seek(_position, SeekOrigin.Begin);
        }
    }
}