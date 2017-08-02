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
    /// Interface Representing a RSA Priv Key
    /// </summary>
    public interface IRsaPrivateKey
    {
        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>
        /// The public key.
        /// </value>
        IRsaPublicKey PublicKey { get; }

        /// <summary>
        /// Gets or sets the private exponent.
        /// </summary>
        /// <value>The private exponent.</value>
        BigInteger PrivateExponent { get; set; }

        /// <summary>
        /// Gets or sets the prime P.
        /// </summary>
        /// <value>The prime P.</value>
        BigInteger PrimeP { get; set; }

        /// <summary>
        /// Gets or sets the prime Q.
        /// </summary>
        /// <value>The prime Q.</value>
        BigInteger PrimeQ { get; set; }

        /// <summary>
        /// Gets or sets the prime exponent P.
        /// </summary>
        /// <value>The prime exponent P.</value>
        BigInteger PrimeExponentP { get; set; }

        /// <summary>
        /// Gets or sets the prime exponent Q.
        /// </summary>
        /// <value>The prime exponent Q.</value>
        BigInteger PrimeExponentQ { get; set; }

        /// <summary>
        /// Gets or sets the CRT coefficient.
        /// </summary>
        /// <value>The CRT coefficient.</value>
        BigInteger CrtCoefficient { get; set; }

        /// <summary>
        /// Gets the key type.
        /// </summary>
        /// <value>The key type.</value>
        KeyType KeyType { get; set; }

        /// <summary>
        /// Gets or sets the size.
        /// </summary>
        /// <value>The size.</value>
        int Size { get; set; }
    }
}