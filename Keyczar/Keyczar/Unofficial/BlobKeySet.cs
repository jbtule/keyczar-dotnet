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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Ionic.Zip;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Reads key set from a single zipped up blob
    /// </summary>
    public class BlobKeySet : IKeySet, IDisposable
    {
        private ZipFile _zipFile;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlobKeySet"/> class.
        /// </summary>
        /// <param name="readStream">The read stream.</param>
        public BlobKeySet(Stream readStream)
        {
            _zipFile = ZipFile.Read(readStream);
        }


        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2202:Do not dispose objects multiple times")]
        public byte[] GetKeyData(int version)
        {
            using (var stream = _zipFile[version.ToString(CultureInfo.InvariantCulture)].OpenReader())
            using (var reader = new BinaryReader(stream))
            {
                return reader.ReadBytes((int) stream.Length);
            }
        }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2202:Do not dispose objects multiple times")]
        public KeyMetadata Metadata
        {
            get
            {
                using (var stream = _zipFile["meta"].OpenReader())
                using (var reader = new StreamReader(stream))
                {
                    return JsonConvert.DeserializeObject<KeyMetadata>(reader.ReadToEnd());
                }
            }
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
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            _zipFile = _zipFile.SafeDispose();
        }
    }
}