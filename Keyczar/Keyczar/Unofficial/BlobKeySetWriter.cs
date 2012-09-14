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
using System.Globalization;
using System.IO;
using Ionic.Zip;
using Keyczar;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Writes keyset to a single zipped up blob
    /// </summary>
    public class BlobKeySetWriter:IKeySetWriter, IDisposable
    {
        private Stream _writeStream;
        ZipFile _zipFile = new NonDestructiveZipFile();

        /// <summary>
        /// Initializes a new instance of the <see cref="BlobKeySetWriter"/> class.
        /// </summary>
        /// <param name="writeStream">The write stream.</param>
        public BlobKeySetWriter(Stream writeStream)
        {
            _writeStream = writeStream;
        }

        /// <summary>
        /// Writes the specified key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="version">The version.</param>
        public void Write(byte[] keyData, int version)
        {
            _zipFile.AddEntry(version.ToString(CultureInfo.InvariantCulture), keyData);
        }
  

        /// <summary>
        /// Writes the specified metadata.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public void Write(KeyMetadata metadata)
        {
            _zipFile.AddEntry("meta", JsonConvert.SerializeObject(metadata));
        }

        /// <summary>
        /// Finishes this writing of the key.
        /// </summary>
        /// <returns></returns>
        public bool Finish()
        {
            _zipFile.Save(_writeStream);
            return true;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(false);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _writeStream.SafeDispose();
            }
            _writeStream = null;

            _zipFile = _zipFile.SafeDispose(); 
        }
    }
}