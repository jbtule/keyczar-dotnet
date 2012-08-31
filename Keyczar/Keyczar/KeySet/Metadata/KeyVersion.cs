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

namespace Keyczar
{
    /// <summary>
    /// Describes key versions
    /// </summary>
    public class KeyVersion:IComparable<KeyVersion>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVersion"/> class.
        /// </summary>
        public KeyVersion()
        {
            Status = KeyStatus.ACTIVE;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVersion"/> class.
        /// </summary>
        /// <param name="keyVersion">The key version.</param>
        public KeyVersion(KeyVersion keyVersion)
        {
            VersionNumber = keyVersion.VersionNumber;
            Exportable = keyVersion.Exportable;
            Status = keyVersion.Status;
        }

        /// <summary>
        /// Gets or sets the version number.
        /// </summary>
        /// <value>The version number.</value>
        public int VersionNumber { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="KeyVersion"/> is exportable.
        /// </summary>
        /// <value><c>true</c> if exportable; otherwise, <c>false</c>.</value>
        public bool Exportable { get; set; }
        /// <summary>
        /// Gets or sets the status.
        /// </summary>
        /// <value>The status.</value>
        public KeyStatus Status { get; set; }

        /// <summary>
        /// Compares to.
        /// </summary>
        /// <param name="other">The other.</param>
        /// <returns></returns>
        public int CompareTo(KeyVersion other)
        {
            if (Status == other.Status)
            {
                if (VersionNumber > other.VersionNumber)
                {
                    return -1;
                }
                if (VersionNumber < other.VersionNumber)
                {
                    return 1;
                }
                return 0;
            }
            if (Status == KeyStatus.PRIMARY)
            {
                return -1;
            }
            if (Status == KeyStatus.ACTIVE && other.Status != KeyStatus.PRIMARY)
            {
                return -1;
            }
            return 1;
        }

        /// <summary>
        /// Equals the specified other.
        /// </summary>
        /// <param name="other">The other.</param>
        /// <returns></returns>
        public bool Equals(KeyVersion other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return other.VersionNumber == VersionNumber;
        }

        /// <summary>
        /// Determines whether the specified <see cref="System.Object"/> is equal to this instance.
        /// </summary>
        /// <param name="obj">The <see cref="System.Object"/> to compare with this instance.</param>
        /// <returns>
        /// 	<c>true</c> if the specified <see cref="System.Object"/> is equal to this instance; otherwise, <c>false</c>.
        /// </returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != typeof (KeyVersion)) return false;
            return Equals((KeyVersion) obj);
        }

        /// <summary>
        /// Returns a hash code for this instance.
        /// </summary>
        /// <returns>
        /// A hash code for this instance, suitable for use in hashing algorithms and data structures like a hash table. 
        /// </returns>
        public override int GetHashCode()
        {
            return VersionNumber;
        }
    }
}