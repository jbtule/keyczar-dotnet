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

namespace Keyczar.Crypto.Streams
{
    /// <summary>
    /// Interface for supporting output of the ciphertext without any other bytes such as the IV
    /// </summary>
    public interface ICipherTextOnly
    {
        /// <summary>
        /// Gets or sets a value indicating whether the output is  the [cipher text only].
        /// </summary>
        /// <value><c>true</c> if [cipher text only]; otherwise, <c>false</c>.</value>
        bool CipherTextOnly { get; set; }

        /// <summary>
        /// Gets or sets the IV.
        /// </summary>
        /// <value>The IV.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance",
            "CA1819:PropertiesShouldNotReturnArrays")]
        byte[] IV { get; set; }
    }

    /// <summary>
    /// Finishing Stream that implements the ICipherTextOnly interface
    /// </summary>
    public abstract class CipherTextOnlyFinishingStream : FinishingStream, ICipherTextOnly
    {
        /// <summary>
        /// Gets or sets a value indicating whether the output is  the [cipher text only].
        /// </summary>
        /// <value><c>true</c> if [cipher text only]; otherwise, <c>false</c>.</value>
        public abstract bool CipherTextOnly { get; set; }

        /// <summary>
        /// Gets or sets the IV.
        /// </summary>
        /// <value>The IV.</value>
        public abstract byte[] IV { get; set; }
    }
}