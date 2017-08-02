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
using Keyczar.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;

namespace Keyczar
{
    /// <summary>
    /// WebBased64 forced type of string
    /// </summary> 
    [JsonConverter(typeof (WebBase64JsonConverter))]
    public class WebBase64
    {
        /// <summary>
        /// Strings the specified bytes.
        /// </summary>
        /// <param name="rawValue">The bytes.</param>
        /// <returns></returns>
        public static implicit operator string(WebBase64 rawValue)
        {
            return rawValue.ToString();
        }

        /// <summary>
        /// Webs the base64.
        /// </summary>
        /// <param name="encodedValue">The web base64.</param>
        /// <returns></returns>
        public static explicit operator WebBase64(string encodedValue)
        {
            return new WebBase64(encodedValue);
        }

        /// <summary>
        /// Froms the bytes.
        /// </summary>
        /// <param name="rawValue">The bytes.</param>
        /// <returns></returns>
        public static WebBase64 FromBytes(byte[] rawValue)
        {
            return new WebBase64(rawValue);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebBase64" /> class.
        /// </summary>
        /// <param name="rawValue">The bytes.</param>
        public WebBase64(byte[] rawValue)
        {
            _rawValue = rawValue;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebBase64" /> class.
        /// </summary>
        /// <param name="encodedValue">The web base64 encoded Value.</param>
        public WebBase64(string encodedValue)
        {
            _rawValue = Util.WebSafeBase64.Decode(encodedValue.ToCharArray());
        }

        /// <summary>
        /// To the bytes.
        /// </summary>
        /// <returns></returns>
        public byte[] ToBytes()
        {
            return (byte[]) _rawValue.Clone();
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return new String(Util.WebSafeBase64.Encode(_rawValue));
        }

        private byte[] _rawValue;

        /// <summary>
        /// Clears this instance.
        /// </summary>
        /// <returns></returns>
        public WebBase64 Clear()
        {
            Util.Secure.Clear(_rawValue);
            return null;
        }
    }
}