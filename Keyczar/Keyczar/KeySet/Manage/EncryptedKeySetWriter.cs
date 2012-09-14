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

using System.Linq;
using Keyczar;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar
{
    /// <summary>
    /// Encrypts a keys before passing them to another keysetwriter
    /// </summary>
    public class EncryptedKeySetWriter : IKeySetWriter
    {
        
        private readonly Encrypter _encrypter;
        private readonly IKeySetWriter _writer;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedKeySetWriter"/> class.
        /// </summary>
        /// <param name="writer">The writer.</param>
        /// <param name="encrypter">The encrypter.</param>
        public EncryptedKeySetWriter(IKeySetWriter writer, Encrypter encrypter)
        {
            _encrypter = encrypter;
            _writer = writer;
        }

        /// <summary>
        /// Writes the specified key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="version">The version.</param>
        public void Write(byte[] keyData, int version)
        {
           var cipherData = _encrypter.Encrypt(keyData);
           _writer.Write(Keyczar.DefaultEncoding.GetBytes(WebSafeBase64.Encode(cipherData)), version);
        }

        /// <summary>
        /// Writes the specified metadata.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public void Write(KeyMetadata metadata)
        {
            metadata.Encrypted = true;
            _writer.Write(metadata);
        }

        /// <summary>
        /// Finishes this writing of the key.
        /// </summary>
        /// <returns></returns>
        public bool Finish()
        {
            return _writer.Finish();
        }
    }
}