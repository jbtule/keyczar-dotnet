/*  Copyright 2013 James Tuley (jay+code@tuley.name)
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

using System.Numerics;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar.Crypto
{
    /// <summary>
    /// Interface representing a RSA pub Key
    /// </summary>
    public interface IRsaPublicKey
    {
        /// <summary>
        /// Gets or sets the modulus.
        /// </summary>
        /// <value>The modulus.</value>
        BigInteger Modulus { get; set; }

        /// <summary>
        /// Gets or sets the public exponent.
        /// </summary>
        /// <value>The public exponent.</value>
        BigInteger PublicExponent { get; set; }

        /// <summary>
        /// Gets or sets the size.
        /// </summary>
        /// <value>The size.</value>
        int Size { get; set; }
    }
}