﻿/*  Copyright 2012 James Tuley (jay+code@tuley.name)
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
using System.Linq;
using Keyczar.Util;

namespace Keyczar
{
    /// <summary>
    /// Base class for standard crypt/sign API
    /// </summary>
    public abstract class KeyczarBase:IDisposable
    {
        /// <summary>
        /// Config Options
        /// </summary>
        public virtual KeyczarConfig Config
        {
            get => _config ?? KeyczarDefaults.DefaultConfig;
            set => _config = value;
        }


        /// <summary>
        /// Buffer size used throughout
        /// </summary>
        protected static readonly int BufferSize = 4096;

        private readonly Dictionary<int, SortedList<KeyVersion, Key>> _hashedKeys;
        private readonly Dictionary<int, List<Key>> _hashedFallbackKeys;

        private readonly Dictionary<int, Key> _versions;
        private readonly KeyVersion _primaryVersion;
        private KeyczarConfig _config = new KeyczarConfig();

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
           Dispose(true);
        }

      
        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            foreach (var key in _hashedKeys.SelectMany(it => it.Value).Select(it => it.Value))
            {
                key.SafeDispose();
            }
            _versions.Clear();
            _hashedKeys.Clear();
            _hashedFallbackKeys.Clear();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyczarBase"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        protected KeyczarBase(string keySetLocation):this(new FileSystemKeySet(keySetLocation))
        {
            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyczarBase"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        protected KeyczarBase(IKeySet keySet)
        {

            var metadata = keySet.Metadata;

            var versions = metadata
                .Versions
                .Select(v =>
                            {
                                var key = keySet.GetKey(v.VersionNumber);
                                return Tuple.Create(key.GetKeyHash(), v, key);
                            })
                .ToList();

            _primaryVersion = metadata.GetPrimaryKeyVersion();

            _versions = versions.ToDictionary(k => k.Item2.VersionNumber, v => v.Item3);

            _hashedKeys = HashKeys(versions);
            _hashedFallbackKeys = HashedFallbackKeys(versions);
        }

        private static Dictionary<int, List<Key>> HashedFallbackKeys(IList<Tuple<byte[], KeyVersion, Key>> versions)
        {
            return versions   
                .Select(t=>new {Hash =t.Item1, Version=t.Item2, CryptKey =t.Item3})
                .SelectMany(k=> k.CryptKey.GetFallbackKeyHash().Select(h=>new{ Hash = h, CryptKey = k.CryptKey}))
                .ToLookup(k=> Utility.ToInt32(k.Hash), v=>v.CryptKey)
                .ToDictionary(k=>k.Key,v=>v.ToList());
        }

        private static Dictionary<int, SortedList<KeyVersion, Key>> HashKeys(IList<Tuple<byte[],KeyVersion,Key>> versions)
        {
            return versions
                .Select(t => new {Hash = t.Item1, Version = t.Item2, CryptKey = t.Item3})
                .ToLookup(k => Utility.ToInt32(k.Hash), v => v)
                .ToDictionary(k => k.Key,
                              v => new SortedList<KeyVersion, Key>(v.ToDictionary(vk => vk.Version, vv => vv.CryptKey)));

        }

        /// <summary>
        /// Gets the primary key.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="System.Data.MissingPrimaryKeyException"></exception>
        protected Key GetPrimaryKey()
        {
            Key key;
            if (_primaryVersion != null && _versions.TryGetValue(_primaryVersion.VersionNumber,out key))
            {
                return key;
            }
            throw new MissingPrimaryKeyException();
        }

        /// <summary>
        /// Gets all keys.
        /// </summary>
        /// <returns></returns>
        internal IEnumerable<Key> GetAllKeys()
            => _versions.OrderByDescending(it => it.Key).Select(it => it.Value);

        /// <summary>
        /// Gets the key using a hash.
        /// </summary>
        /// <param name="hash">The hash.</param>
        /// <returns>List of keys that match the hash</returns>
        internal IEnumerable<Key> GetKey(byte[] hash)
        {
            var hashIndex =Utility.ToInt32(hash);
            SortedList<KeyVersion, Key> list;
            var found = new List<Key>();
            if (_hashedKeys.TryGetValue(hashIndex, out list))
            {
                found.AddRange(list.Select(it => it.Value));
            }

            //Fallback hashes for old/buggy hashes from other keyczar
            List<Key> fallbacklist;
            if (_hashedFallbackKeys.TryGetValue(hashIndex, out fallbacklist)){
                found.AddRange(fallbacklist);
            }

            //For special imported keys
            if(_hashedKeys.TryGetValue(0, out list)){
                found.AddRange(list.Select(it=>it.Value));
            }
            return found.Any() ? (IEnumerable<Key>)found : new Key[] {null};
        }


    }
}
