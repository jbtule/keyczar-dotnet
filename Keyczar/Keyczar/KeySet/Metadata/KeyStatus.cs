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

namespace Keyczar
{
    /// <summary>
    /// The key status
    /// </summary>
    public class KeyStatus:Util.StringType
    {
        /// <summary>
        /// Primary
        /// </summary>
        public static readonly KeyStatus PRIMARY = "PRIMARY";
        /// <summary>
        /// Active
        /// </summary>
        public static readonly KeyStatus ACTIVE = "ACTIVE";
        /// <summary>
        /// Inactive
        /// </summary>
        public static readonly KeyStatus INACTIVE = "INACTIVE";

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="KeyStatus"/>.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        /// <returns>The result of the conversion.</returns>
        public static  implicit operator KeyStatus(string identifer)
        {
            return new KeyStatus(identifer);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyStatus"/> class.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        public KeyStatus(string identifer): base(identifer)
        {
        }
    }
}