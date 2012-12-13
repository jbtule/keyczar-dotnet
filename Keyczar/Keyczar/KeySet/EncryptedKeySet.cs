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
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Wraps a key set to decrypt it
    /// </summary>
    public class EncryptedKeySet : IKeySet
    {
        private readonly IKeySet _keySet;
        private readonly Crypter _crypter;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedKeySet"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        /// <param name="crypter">The crypter.</param>
        public EncryptedKeySet(string keySetLocation, Crypter crypter)
            :this(new KeySet(keySetLocation), crypter )
        {
            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedKeySet"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <param name="crypter">The crypter.</param>
        public EncryptedKeySet(IKeySet keySet, Crypter crypter)
        {
            _keySet = keySet;

            _crypter = crypter;
        }

        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {
            var cipherData = _keySet.GetKeyData(version);
            if (!Metadata.Encrypted)
            {
                return cipherData;
            }
         
           var cipherString = Keyczar.RawStringEncoding.GetString(cipherData);
           return _crypter.Decrypt(WebSafeBase64.Decode(cipherString.ToCharArray()));
        }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        public KeyMetadata Metadata
        {
            get { return _keySet.Metadata; }
        }

    }
}
