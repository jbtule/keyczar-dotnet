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
    public class PbeKeySet : ILayeredKeySet, IDisposable
    {
        private IKeySet _keySet;
        private CachedPrompt _password;

        public static Func<IKeySet, PbeKeySet> Creator(Func<string> passwordPrompt)
        {
            return keySet => new PbeKeySet(keySet, passwordPrompt);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PbeKeySet"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        /// <param name="passwordPrompt">The password prompt.</param>
        [Obsolete("Use `KeySet.LayerSecurity` with `FileSystemKeyset.Creator` and `PbeKeySet.Creator`")]
        public PbeKeySet(string keySetLocation, Func<string> passwordPrompt)
            : this(new FileSystemKeySet(keySetLocation), passwordPrompt)
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

            var cipherString = Keyczar.RawStringEncoding.GetString(cipherData);
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

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _keySet = _keySet.SafeDispose();
                    _password = _password.SafeDispose();
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