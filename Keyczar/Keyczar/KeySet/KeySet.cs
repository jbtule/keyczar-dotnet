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
    public class KeySet : FileSystemKeySet
    {
        public static IKeySet LayerSecurity(Func<IRootProviderKeySet> rootKeyetCreator,
                                      params Func<IKeySet, ILayeredKeySet>[] layeredKeysetCreators)
        {
            IKeySet keyset = rootKeyetCreator();
            foreach(var layered in layeredKeysetCreators){
                keyset = layered(keyset);
            }
            return keyset;
        }

		[Obsolete("KeySet.Creator doesn't exist", error: true)]
		public static new Func<FileSystemKeySet> Creator(string location)
		{
			throw new NotSupportedException();
		}

        [Obsolete("Use `FileSystemKeyset` instead")]
        public KeySet(string keySetLocation) : base(keySetLocation)
        {
        }
    }
}