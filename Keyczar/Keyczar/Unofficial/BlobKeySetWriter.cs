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
using Keyczar;
using Keyczar.Util;
using Newtonsoft.Json;
using SharpCompress.Writers.Zip;
using SharpCompress.Writers;
using SharpCompress.Common;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Writes keyset to a single zipped up blob
    /// </summary>
    public class BlobKeySetWriter : IRootProviderKeySetWriter, IDisposable, INonSeparatedMetadataAndKey
    {

        public static Func<BlobKeySetWriter> Creator(Stream writeStream) 
            => () => new BlobKeySetWriter(writeStream);

        private Stream _writeStream;
        private ZipWriter _zipFile;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlobKeySetWriter"/> class.
        /// </summary>
        /// <param name="writeStream">The write stream.</param>
        public BlobKeySetWriter(Stream writeStream)
        {
            _writeStream = writeStream;
            _zipFile = new NondestructiveZipFile(_writeStream, new ZipWriterOptions(SharpCompress.Common.CompressionType.Deflate));
        }

        /// <summary>
        /// Writes the specified key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="version">The version.</param>
        public void Write(byte[] keyData, int version)
        {
            _zipFile.Write(version.ToString(CultureInfo.InvariantCulture), new MemoryStream(keyData));
        }

        /// <summary>
        /// Config Options
        /// </summary>
        public KeyczarConfig Config { get; set; }



        /// <summary>
        /// Writes the specified metadata.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public void Write(KeyMetadata metadata)
        {
            var bytes = this.GetConfig().RawStringEncoding.GetBytes(metadata.ToJson());
            _zipFile.Write("meta",new MemoryStream(bytes));
        }

        /// <summary>
        /// Finishes this writing of the key.
        /// </summary>
        /// <returns></returns>
        public bool Finish()
        {
            return true;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _writeStream = _writeStream.SafeDispose();
                    _zipFile = _zipFile.SafeDispose();
                }

                disposedValue = true;
            }
        }

   

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
     
        }
        #endregion


    }
}