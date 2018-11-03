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
using SharpCompress.Archives.Zip;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Reads key set from a single zipped up blob
    /// </summary>
    public class BlobKeySet : IRootProviderKeySet, IDisposable
    {
        public static Func<BlobKeySet> Creator(Stream readStream)
        {
            return () => new BlobKeySet(readStream);
        }


        private ZipArchive _zipFile;


        /// <summary>
        /// Initializes a new instance of the <see cref="BlobKeySet"/> class.
        /// </summary>
        /// <param name="readStream">The read stream.</param>
        public BlobKeySet(Stream readStream)
        {
            _zipFile = ZipArchive.Open(readStream);
        }

        /// <summary>
        /// Config Options
        /// </summary>
        public KeyczarConfig Config { get; set; }



        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2202:Do not dispose objects multiple times")]
        public byte[] GetKeyData(int version)
        {
            var keyEntry =_zipFile.Entries.First(entry => entry.Key == version.ToString(CultureInfo.InvariantCulture));
            using (var stream = keyEntry.OpenEntryStream())
            using (var reader = new BinaryReader(stream))
            {
                return reader.ReadBytes((int) keyEntry.Size);
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
                var metaEntry = _zipFile.Entries.First(entry => entry.Key == "meta");
                using (var stream = metaEntry.OpenEntryStream())
                using (var reader = new StreamReader(stream))
                {
                    return JsonConvert.DeserializeObject<KeyMetadata>(reader.ReadToEnd());
                }
            }
        }

        #region IDisposable Support
        private bool _disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _zipFile = _zipFile.SafeDispose();
                }
                _disposedValue = true;
            }
        }


        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion

    }
}