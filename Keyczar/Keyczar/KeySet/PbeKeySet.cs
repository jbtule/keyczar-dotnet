using System;
using Keyczar.Pbe;
using Keyczar.Util;
using Newtonsoft.Json;

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


namespace Keyczar
{
    /// <summary>
    /// Password based encrypted Key Set
    /// </summary>
    public class PbeKeySet: IKeySet,IDisposable
    {
        private IKeySet _keySet;
        private CachedPrompt _password;


        /// <summary>
        /// Initializes a new instance of the <see cref="PbeKeySet"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        /// <param name="passwordPrompt">The password prompt.</param>
        public PbeKeySet(string keySetLocation, Func<string> passwordPrompt)
            : this(new KeySet(keySetLocation), passwordPrompt)
        {
            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedKeySet"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <param name="passwordPrompt">The password prompt.</param>
        public PbeKeySet(IKeySet keySet, Func<string> passwordPrompt)
        {
            _keySet = keySet;

            _password = CachedPrompt.Password(passwordPrompt);
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

            var cipherString = Keyczar.DefaultEncoding.GetString(cipherData);
            var store = JsonConvert.DeserializeObject<PbeKeyStore>(cipherString);

            return store.DecryptKeyData(_password.Prompt);
        }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        public KeyMetadata Metadata
        {
            get { return _keySet.Metadata; }
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
        /// Finalizes an instance of the <see cref="PbeKeySet" /> class.
        /// </summary>
        ~PbeKeySet()
        {
            Dispose(false);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {

            _keySet = null;
            _password = _password.SafeDispose();
        }
    }
}