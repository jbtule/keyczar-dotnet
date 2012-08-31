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

namespace Keyczar
{
    /// <summary>
    /// Interface for mechanisms to store keysets
    /// </summary>
    public interface IKeySetWriter : IRawKeySetWriter
    {

        /// <summary>
        /// Writes the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="version">The version.</param>
        void Write(Key key, int version);

        /// <summary>
        /// Writes the specified metadata.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        void Write(KeyMetadata metadata);

        /// <summary>
        /// Finishes this writing of the key.
        /// </summary>
        /// <returns></returns>
        bool Finish();
    }

    /// <summary>
    /// Interface to access raw data used for encryption
    /// </summary>
    public interface IRawKeySetWriter 
    {
        /// <summary>
        /// Writes the specified key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="version">The version.</param>
        void Write(byte[] keyData, int version);
    }
}
