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

using System.ComponentModel;

namespace Keyczar
{
    /// <summary>
    /// Key purpose
    /// </summary>'
    [ImmutableObject(true)]
    public class KeyPurpose:Util.StringType
    {

        /// <summary>
        /// Decrypt and Encrypt
        /// </summary>
        public static readonly KeyPurpose DECRYPT_AND_ENCRYPT = "DECRYPT_AND_ENCRYPT";
        /// <summary>
        /// Encrypt
        /// </summary>
        public static readonly KeyPurpose ENCRYPT = "ENCRYPT";
        /// <summary>
        /// Sign and verify
        /// </summary>
        public static readonly KeyPurpose SIGN_AND_VERIFY = "SIGN_AND_VERIFY";
        /// <summary>
        /// Verify
        /// </summary>
        public static readonly KeyPurpose VERIFY = "VERIFY";

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="KeyPurpose"/>.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The result of the conversion.</returns>
        public static  implicit operator KeyPurpose(string identifier)
        {
            return new KeyPurpose(identifier);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyPurpose"/> class.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        public KeyPurpose(string identifier) : base(identifier)
        {
        }
    }
}