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
    /// The key status
    /// </summary>
    [ImmutableObject(true)]
    public class KeyStatus : Util.StringType
    {
        /// <summary>
        /// Primary
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyStatus Primary = "PRIMARY";

        /// <summary>
        /// Active
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyStatus Active = "ACTIVE";

        /// <summary>
        /// Inactive
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyStatus Inactive = "INACTIVE";

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="KeyStatus"/>.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        /// <returns>The result of the conversion.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Constructor Is Alternative")]
        public static implicit operator KeyStatus(string identifier)
        {
            return new KeyStatus(identifier);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyStatus"/> class.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        public KeyStatus(string identifier) : base(identifier)
        {
        }
    }
}