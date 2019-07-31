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
using System.Linq;

namespace Keyczar
{
    public sealed class KeySetWriter : FileSystemKeySetWriter
    {
        public static IKeySetWriter LayerSecurity(Func<IRootProviderKeySetWriter> rootKeySetWriterCreator,
								   params Func<IKeySetWriter, ILayeredKeySetWriter>[] layeredKeySetWriterCreators)
		{
			IKeySetWriter writer = rootKeySetWriterCreator();
			return layeredKeySetWriterCreators.Aggregate(writer, (current, layered) => layered(current));
		}

        [Obsolete("KeySetWriter.Creator doesn't exist", error:true)]
        public new static Func<FileSystemKeySetWriter> Creator(string location, bool overwrite = false) 
	        => throw new NotSupportedException();


        [Obsolete("Use FileSystemKeySetWriter instead")]
        public KeySetWriter(string location, bool overwrite = false) : base(location, overwrite)
        {
        }
    }
}