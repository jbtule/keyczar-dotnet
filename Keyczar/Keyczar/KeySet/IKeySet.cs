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

namespace Keyczar
{
    /// <summary>
    /// Extension Methods for IKeySet
    /// </summary>
    public static class StandardKeySetOperations
    {
        /// <summary>
        /// Get's deep copy of Key from IKeyset
        /// </summary>
        /// <param name="keySet">The keyset.</param>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public static Key GetKey(this IKeySet keySet, int version)
        {
            var keyData = keySet.GetKeyData(version);
            var keyType = keySet.Metadata.GetKeyType(version);
            var key = Key.Read(keyType, keyData, keySet.Config);
            keyData.Clear();
            return key;
        }

        public static KeyczarConfig GetConfig(this IKeySet keySet)
        {
            return keySet.Config = keySet.Config ?? new KeyczarConfig();
        }
    }

    public interface IRootProviderKeySet:IKeySet{
        
    }

	public interface ILayeredKeySet : IKeySet
	{

	}

    /// <summary>
    /// Defines methods for getting keys out of a key set
    /// </summary>
    public interface IKeySet:IDisposable
    {
        
        KeyczarConfig Config { get; set; }

        
        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        KeyMetadata Metadata { get; }

        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        byte[] GetKeyData(int version);
    }
}