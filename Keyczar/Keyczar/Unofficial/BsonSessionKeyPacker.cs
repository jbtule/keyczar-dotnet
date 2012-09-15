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
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Packs a key including type into a single bson binary array
    /// </summary>
    public class BsonSessionKeyPacker:ISessionKeyPacker
    {
        /// <summary>
        /// Format for packing the key in bson
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public class KeyPack<T> where T : Key
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="KeyPack&lt;T&gt;"/> class.
            /// </summary>
            /// <param name="key">The key.</param>
            public KeyPack(T key)
            {
                Type = key.Type;
                Key = key;
            }

            /// <summary>
            /// Gets or sets the type.
            /// </summary>
            /// <value>The type.</value>
            public KeyType Type { get; set; }
            /// <summary>
            /// Gets or sets the key.
            /// </summary>
            /// <value>The key.</value>
            public T Key { get; set; }

        }

        private KeyPack<T> PackIt<T>(T key) where T : Key
        {
            return new KeyPack<T>(key);
        }

        /// <summary>
        /// Packs the specified key into bytes
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public byte[] Pack(Key key)
        {

            return Utility.ToBson(PackIt((dynamic) key));
          
        }

        /// <summary>
        /// Unpacks the specified bytes into a key.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns></returns>
        public Key Unpack(byte[] bytes)
        {
            using (var input = new MemoryStream(bytes)) 
            using (var input2 = new MemoryStream(bytes)) 
            {
                var reader = new BsonReader(input);
                var serializer = new JsonSerializer ();
                var val = JToken.ReadFrom(reader);
                reader = new BsonReader(input2);
                var keyType = (KeyType)(string)val["type"];
                var pack = (dynamic)serializer.Deserialize(reader, typeof(KeyPack<>).MakeGenericType(keyType.Type));
                return pack.Key;
            }
        }
    }
}
