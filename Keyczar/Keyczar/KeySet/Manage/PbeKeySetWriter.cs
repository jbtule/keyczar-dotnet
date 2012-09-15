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
using Keyczar.Pbe;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar
{
    /// <summary>
    /// Password Based Encrypted Key Set
    /// </summary>
    public class PbeKeySetWriter:IKeySetWriter,IDisposable
    {
    
        private IKeySetWriter _writer;
        private readonly int _interationsCount;
        private CachedPrompt _password;


        /// <summary>
        /// Initializes a new instance of the <see cref="PbeKeySetWriter"/> class.
        /// </summary>
        /// <param name="writer">The writer.</param>
        /// <param name="passwordPrompt">The password prompt.</param>
        /// <param name="interationsCount">The interations count.</param>
        public PbeKeySetWriter(IKeySetWriter writer, Func<string> passwordPrompt, int interationsCount = 4096)
        {
            _password = CachedPrompt.Password(passwordPrompt);
            _writer = writer;
            _interationsCount = interationsCount;
        }


        /// <summary>
        /// Writes the specified key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="version">The version.</param>
        public void Write(byte[] keyData, int version)
        {
            var keyStore = PbeKeyStore.EncryptKeyData(keyData, _password.Prompt, _interationsCount);
            _writer.Write(Keyczar.DefaultEncoding.GetBytes(keyStore.ToJson()), version);
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

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _writer = null;
            _password = _password.SafeDispose();
        }
    }
}