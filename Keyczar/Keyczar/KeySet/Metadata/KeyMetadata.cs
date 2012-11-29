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
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace Keyczar
{

    /// <summary>
    /// Metadata for a keyset
    /// </summary>
    
    public class KeyMetadata
    {

        /// <summary>
        /// Reads the specified meta data.
        /// </summary>
        /// <param name="metadata">The meta data.</param>
        /// <returns></returns>
        public static KeyMetadata Read(string metadata)
        {
            return JsonConvert.DeserializeObject<KeyMetadata>(metadata);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata"/> class.
        /// </summary>
        public KeyMetadata()
        {
            Versions= new List<KeyVersion>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata"/> class.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public KeyMetadata(KeyMetadata metadata)
        {
            Name = metadata.Name;
            Purpose = metadata.Purpose;
            KeyType = metadata.KeyType;
            Encrypted = metadata.Encrypted;
            Versions = metadata.Versions.Select(it => new KeyVersion(it)).ToList();
        }


        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }
        /// <summary>
        /// Gets or sets the purpose.
        /// </summary>
        /// <value>The purpose.</value>
        public KeyPurpose Purpose { get; set; }

        /// <summary>
        /// Gets or sets the key type.
        /// </summary>
        /// <value>The key type.</value>
        [JsonProperty("Type")]
        public KeyType KeyType { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="KeyMetadata"/> is encrypted.
        /// </summary>
        /// <value><c>true</c> if encrypted; otherwise, <c>false</c>.</value>
        public bool Encrypted { get; set; }

        /// <summary>
        /// Gets or sets the versions.
        /// </summary>
        /// <value>The versions.</value>
        public IList<KeyVersion> Versions { get; set; }

        
    }
}
