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
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Newtonsoft.Json;
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Mutable Keyset to allow modification and saving
    /// </summary>
    public class MutableKeySet : IKeySet, IDisposable
    {
        private KeyMetadata _metadata;
        private IDictionary<int,Key> _keys = new Dictionary<int, Key>();
        private bool onlyMetaChanged = true;

        /// <summary>
        /// Initializes a new instance of the <see cref="MutableKeySet" /> class.
        /// </summary>
        /// <param name="location">The location.</param>
        public MutableKeySet(string location):this(new KeySet(location))
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MutableKeySet" /> class.
        /// </summary>
        /// <param name="emptyKeySet">The metadata of an empty key set.</param>
        /// <exception cref="InvalidKeySetException">Only empty key sets can be created using just the KeyMetadata.</exception>
        public MutableKeySet(KeyMetadata emptyKeySet)
        {
            _metadata = emptyKeySet;
            if (_metadata.Versions.Any())
            {
                throw new InvalidKeySetException("Only empty key sets can be created using just the KeyMetadata.");
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MutableKeySet"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        public MutableKeySet(IKeySet keySet)
        {
            _metadata = keySet.Metadata;

            foreach (var version in keySet.Metadata.Versions)
            {
                //Easy way to deep copy keys
                var keyData = keySet.GetKeyData(version.VersionNumber);
                var key = Key.Read(_metadata.Type, keyData);
                keyData.Clear();
                _keys.Add(version.VersionNumber, key);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MutableKeySet"/> class.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        /// <param name="keys">The keys.</param>
        protected MutableKeySet(KeyMetadata metadata, IDictionary<int, Key> keys)
        {
            _metadata = metadata;
            _keys = keys;
            onlyMetaChanged = false;
        }

        /// <summary>
        /// Saves using the specified writer.
        /// </summary>
        /// <param name="writer">The writer.</param>
        /// <returns>true if successful</returns>
        public bool Save(IKeySetWriter writer)
        {
            writer.Write(_metadata);
            if (!onlyMetaChanged) { 
                for (int i = 1; i <= _keys.Count; i++)
                {
                    var key = _keys[i];
                    writer.Write(key, i);
                }
            }
            return writer.Finish();
        }

        /// <summary>
        /// Adds the key.
        /// </summary>
        /// <param name="status">The status.</param>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="options">The options. dictionary or annoymous type of properties to set</param>
        /// <returns></returns>
        public int AddKey(KeyStatus status, int keySize =0, object options=null)
        {
			Key key;
			bool loop;
			do{
				loop = false;
            	key = Key.Generate(_metadata.Type, keySize);
	            if (options != null)
	            {
	                Utility.CopyProperties((dynamic) options, key);
	            }
				foreach(var existingkey in _keys){
					var newhash =Util.Utility.ToInt32(key.GetKeyHash());
					var existhash = Utility.ToInt32(existingkey.Value.GetKeyHash());
					if(newhash == existhash){
						loop = true;
						break;
					}
				}
			}while(loop);
			return AddKey(status, key);
        }

        /// <summary>
        /// Adds the key.
        /// </summary>
        /// <param name="status">The status.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public int AddKey(KeyStatus status, Key key)
        {
            int lastVersion = 0;
            foreach (var version in _metadata.Versions)
            {
                if (status == KeyStatus.PRIMARY && version.Status == KeyStatus.PRIMARY)
                    version.Status = KeyStatus.ACTIVE;
                lastVersion = Math.Max(lastVersion, version.VersionNumber);
            }
            _metadata.Versions.Add(new KeyVersion() { Status = status, VersionNumber = ++lastVersion });
     
            _keys.Add(lastVersion, key);
            onlyMetaChanged = false;
            return lastVersion;
        }

        /// <summary>
        /// Promotes the specified version.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public KeyStatus Promote(int version)
        {
           var ver = Metadata.Versions.FirstOrDefault(it => it.VersionNumber == version);
           if (ver == null)
               return null;

           if (ver.Status == KeyStatus.ACTIVE)
           {
               foreach (var verPrim in Metadata.Versions.Where(it=>it.Status == KeyStatus.PRIMARY))
               {
                   verPrim.Status = KeyStatus.ACTIVE;
               }
               ver.Status = KeyStatus.PRIMARY;
           }
           else if (ver.Status == KeyStatus.INACTIVE)
           {
               ver.Status = KeyStatus.ACTIVE;
           }

           return ver.Status;
        }

        /// <summary>
        /// Demotes the specified version.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public KeyStatus Demote(int version)
        {
            var ver = Metadata.Versions.FirstOrDefault(it => it.VersionNumber == version);
            if (ver == null)
                return null;

            if (ver.Status == KeyStatus.PRIMARY)
            {
                ver.Status = KeyStatus.ACTIVE;
            }
            else if (ver.Status == KeyStatus.ACTIVE)
            {
                ver.Status = KeyStatus.INACTIVE;
            }

            return ver.Status;
        }

        /// <summary>
        /// Revokes the specified version.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public bool Revoke(int version)
        {
            var ver = Metadata.Versions.FirstOrDefault(it => it.VersionNumber == version);
            if (ver == null)
                return false;
            if(ver.Status != KeyStatus.INACTIVE)
                return false;
            Metadata.Versions.Remove(ver);
            return true;
        }

        /// <summary>
        /// Returns keyset with only the public keys.
        /// </summary>
        /// <returns></returns>
        public MutableKeySet PublicKey()
        {
            if(!typeof(IPrivateKey).IsAssignableFrom(Metadata.Type.Type))
            {
                return null;
            }

            var newMeta = new KeyMetadata(Metadata);
            newMeta.Purpose = newMeta.Purpose == KeyPurpose.SIGN_AND_VERIFY
                ? KeyPurpose.VERIFY 
                : KeyPurpose.ENCRYPT;

           var copiedKeys = _keys.Select(p => new {p.Key, ((IPrivateKey) p.Value).PublicKey})
                .Select(p => new {p.Key, p.PublicKey.Type, Value = Keyczar.DefaultEncoding.GetBytes(p.PublicKey.ToJson())})
                .Select(p => new {p.Key, Value = Key.Read(p.Type,p.Value)});

            newMeta.Type = copiedKeys.Select(it => it.Value.Type).First();

           return new MutableKeySet(newMeta, copiedKeys.ToDictionary(k => k.Key, v => v.Value));
        }

        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {
            return Keyczar.DefaultEncoding.GetBytes(_keys[version].ToJson());
        }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        public KeyMetadata Metadata
        {
            get { return _metadata; }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            foreach (var keyPair in _keys)
            {
                keyPair.Value.SafeDispose();
            }
            _keys.Clear();
            _metadata = null;
        }
    }

   
}
