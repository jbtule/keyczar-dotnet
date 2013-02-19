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
    public class BsonSessionKeyPacker : ISessionKeyPacker
    {
        /// <summary>
        /// Format for packing the key in bson
        /// </summary>
        public class KeyPack
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="KeyPack" /> class.
            /// </summary>
            /// <param name="key">The key.</param>
            public KeyPack(Key key)
            {
                KeyType = key.KeyType;
                Key = key;
            }

            /// <summary>
            /// Gets or sets the type.
            /// </summary>
            /// <value>The type.</value>
            [JsonProperty("Type")]
            public KeyType KeyType { get; set; }

            /// <summary>
            /// Gets or sets the key.
            /// </summary>
            /// <value>The key.</value>
            public Key Key { get; set; }
        }

        private static KeyPack PackIt(Key key)
        {
            return new KeyPack(key);
        }

        /// <summary>
        /// Packs the specified key into bytes
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public byte[] Pack(Key key)
        {
            return Utility.ToBson(PackIt(key));
        }

        /// <summary>
        /// Unpacks the specified bytes into a key.
        /// </summary>
        /// <param name="data">The bytes.</param>
        /// <returns></returns>
        public Key Unpack(byte[] data)
        {
            using (var input = new MemoryStream(data))
            {
                var reader = new BsonReader(input);
                var val = JToken.ReadFrom(reader);
                var keyType = (KeyType) (string) val["type"];
                var keyString = val["key"].ToString();
                using (var stringReader = new StringReader(keyString))
                {
                    var jsonSerializer =
                        JsonSerializer.Create(new JsonSerializerSettings
                                                  {
                                                      ContractResolver =
                                                          new CamelCasePropertyNamesContractResolver
                                                          ()
                                                  });
                    return
                        (Key)
                        jsonSerializer.Deserialize(new WebSafeBase64ByteConverter.RawJsonReader(stringReader),
                                                   keyType.RepresentedType);
                }
            }
        }
    }
}