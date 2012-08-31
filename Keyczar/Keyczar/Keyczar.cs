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

namespace Keyczar
{
    /// <summary>
    /// Base class for standard crypt/sign API
    /// </summary>
    public abstract class Keyczar:IDisposable
    {
        /// <summary>
        /// Default encoding used through out (UTF8)
        /// </summary>
        public static readonly Encoding DefaultEncoding = Encoding.UTF8;

        /// <summary>
        /// Key hash length
        /// </summary>
        public static readonly int KEY_HASH_LENGTH = 4;
        /// <summary>
        /// Keyczar format version
        /// </summary>
        public static readonly byte FORMAT_VERSION = 0;
        /// <summary>
        /// Keyczar format version bytes for header
        /// </summary>
        public static readonly byte[] FORMAT_BYTES = new []{ FORMAT_VERSION };
        /// <summary>
        /// Full keyczar format header length
        /// </summary>
        public static readonly int HEADER_LENGTH = FORMAT_BYTES.Length + KEY_HASH_LENGTH;

        /// <summary>
        /// Buffer size used throughout
        /// </summary>
        protected static int BUFFER_SIZE = 4096;

        private readonly Dictionary<int, SortedList<KeyVersion, Key>> _hashedKeys;
        private readonly Dictionary<int, Key> _versions;
        private readonly KeyVersion _primaryVersion;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public virtual void Dispose()
        {
            foreach (var key in _hashedKeys.SelectMany(it => it.Value).Select(it => it.Value))
            {
                key.Dispose();
            }
            _versions.Clear();
            _hashedKeys.Clear();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Keyczar"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        protected Keyczar(string keySetLocation):this(new KeySet(keySetLocation))
        {
            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Keyczar"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        protected Keyczar(IKeySet keySet)
        {

            var metadata = keySet.Metadata;

            var versions = metadata
                .Versions
                .Select(v =>
                            {
                                var key = keySet.GetKey(v.VersionNumber);
                                return new {Hash = key.GetKeyHash(), Version = v, CryptKey = key};
                            })
                .ToList();

            _primaryVersion = metadata.Versions.SingleOrDefault(it => it.Status == KeyStatus.PRIMARY);

            _versions = versions.ToDictionary(k => k.Version.VersionNumber, v => v.CryptKey);

            _hashedKeys = versions
                .ToLookup(k => k.Hash, v => v)
                .ToDictionary(k => BitConverter.ToInt32(k.Key,0), v =>
                                              {
                                                  var list = new SortedList<KeyVersion, Key>();
                                                  foreach (var pair in v)
                                                  {
                                                      list.Add(pair.Version,pair.CryptKey);
                                                  }
                                                  return list;
                                              });

        }

        /// <summary>
        /// Gets the primary key.
        /// </summary>
        /// <returns></returns>
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
        protected IEnumerable<Key> GetAllKeys()
        {
           return _versions.OrderByDescending(it => it.Key).Select(it => it.Value);
        }

        /// <summary>
        /// Gets the key using a hash.
        /// </summary>
        /// <param name="hash">The hash.</param>
        /// <returns></returns>
        protected Key GetKey(byte[] hash)
        {
            var hashIndex =BitConverter.ToInt32(hash, 0);
            SortedList<KeyVersion, Key> list;
            if (_hashedKeys.TryGetValue(hashIndex, out list))
            {
                return list.Select(it=>it.Value).FirstOrDefault();
            }
            return null;
        }


    }
}
