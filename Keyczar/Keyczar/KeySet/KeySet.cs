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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Keyczar
{
    /// <summary>
    /// standard key set
    /// </summary>
    public class KeySet : IKeySet
    {
        private readonly string _location;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeySet"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public KeySet(string keySetLocation)
        {
            _location = keySetLocation;
        }

        /// <summary>
        /// Gets the key.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public Key GetKey(int version)
        {
            if (Metadata.Encrypted)
                throw new InvalidKeySetException("Key set is encrypted.");
            return Key.Read(Metadata.Type, GetKeyData(version));

        }

        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {      
            var path = Path.Combine(_location, version.ToString(CultureInfo.InvariantCulture));
            return File.ReadAllBytes(path);
        }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        public KeyMetadata Metadata
        {
            get
            {
                var path = Path.Combine(_location, "meta");
                return KeyMetadata.Read(File.ReadAllText(path,Keyczar.DefaultEncoding));
                
            }
        }
    }
}
