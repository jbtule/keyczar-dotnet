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
        private IDictionary<int, Key> _keys = new Dictionary<int, Key>();
        private bool onlyMetaChanged = true;

        /// <summary>
        /// Initializes a new instance of the <see cref="MutableKeySet" /> class.
        /// </summary>
        /// <param name="location">The location.</param>
        public MutableKeySet(string location) : this(new FileSystemKeySet(location))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MutableKeySet" /> class.
        /// </summary>
        /// <param name="emptyKeySet">The metadata of an empty key set.</param>
        /// <exception cref="InvalidKeySetException">Only empty key sets can be created using just the KeyMetadata.</exception>
        public MutableKeySet(KeyMetadata emptyKeySet)
        {
            _metadata = new KeyMetadata(emptyKeySet);
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
            _metadata = new KeyMetadata(keySet.Metadata);

            foreach (var version in keySet.Metadata.Versions)
            {
                //Easy way to deep copy keys
                var keyData = keySet.GetKeyData(version.VersionNumber);
                var keyType = _metadata.GetKeyType(version.VersionNumber);
                var key = Key.Read(keyType, keyData);
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

            if (!onlyMetaChanged || writer is INonSeparatedMetadataAndKey)
            {
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
        /// <param name="type">The Key type.</param>
        /// <param name="options">The options. dictionary or annoymous type of properties to set</param>
        /// <returns></returns>

        public int AddKey(KeyStatus status, int keySize =0, KeyType type =null,object options=null)
        {
            if (type != null && Metadata.Kind != null && type.Kind != Metadata.Kind)
            {
                throw new InvalidKeyTypeException(String.Format("Keyset only supports {0} keys", Metadata.Kind));
            }

		      	Key key;
		      	bool loop;
		      	do{
			        	loop = false;
                key = Key.Generate(type??_metadata.DefaultKeyType, keySize);
	            if (options != null)
	            {
	                var dict = options as IDictionary<string, object>;
                    if(dict ==null)
	                    Utility.CopyProperties(options, key);

                    else
                        Utility.CopyProperties(dict, key);
                }
                foreach (var existingkey in _keys)
                {
                    var newhash = Util.Utility.ToInt32(key.GetKeyHash());
                    var existhash = Utility.ToInt32(existingkey.Value.GetKeyHash());
                    if (newhash == existhash)
                    {
                        loop = true;
                        break;
                    }
                }
            } while (loop);
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
            if (key.KeyType.Kind != Metadata.Kind && Metadata.Kind != null)
            {
                throw new InvalidKeyTypeException(String.Format("Keyset only supports {0} keys", Metadata.Kind));
            }

#pragma warning disable 618
            if (Metadata.KeyType != null)
            {
                //Once We add a key our new format shouldn't track the old one anymore
                Metadata.KeyType = null;
            }
#pragma warning restore 618

            int lastVersion = 0;
            foreach (var version in _metadata.Versions)
            {
                if (status == KeyStatus.Primary && version.Status == KeyStatus.Primary)
                    version.Status = KeyStatus.Active;
                lastVersion = Math.Max(lastVersion, version.VersionNumber);
            }

            _metadata.Versions.Add(new KeyVersion(status, ++lastVersion, key));
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

            if (ver.Status == KeyStatus.Active)
            {
                foreach (var verPrim in Metadata.Versions.Where(it => it.Status == KeyStatus.Primary))
                {
                    verPrim.Status = KeyStatus.Active;
                }
                ver.Status = KeyStatus.Primary;
            }
            else if (ver.Status == KeyStatus.Inactive)
            {
                ver.Status = KeyStatus.Active;
            }

            return ver.Status;
        }

        /// <summary>
        /// Forces the flag for the says the key data has change.
        /// </summary>
        public void ForceKeyDataChange()
        {
            onlyMetaChanged = false;
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

            if (ver.Status == KeyStatus.Primary)
            {
                ver.Status = KeyStatus.Active;
            }
            else if (ver.Status == KeyStatus.Active)
            {
                ver.Status = KeyStatus.Inactive;
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
            if (ver.Status != KeyStatus.Inactive)
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

            if(Metadata.Kind != KeyKind.Private)
            {
                return null;
            }

            var newMeta = new KeyMetadata(Metadata);
            newMeta.Purpose = newMeta.Purpose == KeyPurpose.SignAndVerify
                                  ? KeyPurpose.Verify
                                  : KeyPurpose.Encrypt;

#pragma warning disable 618
            newMeta.KeyType = null; //Keytype only matters to old style empty keysets 
#pragma warning restore 618

            newMeta.Kind = KeyKind.Public;

            var copiedKeys = _keys.Select(p => new {p.Key, ((IPrivateKey) p.Value).PublicKey})
                .Select(p => new {p.Key, Type = p.PublicKey.KeyType, Value = Keyczar.RawStringEncoding.GetBytes(p.PublicKey.ToJson())})
                .Select(p => new {p.Key, Value = Key.Read(p.Type,p.Value)}).ToList();


            //Update versions to public key type
            foreach (var key in copiedKeys)
            {
               var newVersion = newMeta.Versions.Single(it => it.VersionNumber == key.Key);
                newVersion.KeyType = key.Value.KeyType;
            }

            return new MutableKeySet(newMeta, copiedKeys.ToDictionary(k => k.Key, v => v.Value));
        }

        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {
            return Keyczar.RawStringEncoding.GetBytes(_keys[version].ToJson());
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
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="MutableKeySet" /> class.
        /// </summary>
        ~MutableKeySet()
        {
            Dispose(false);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
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