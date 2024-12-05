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
using System.IO;
using System.Linq;
using System.Text;
using ICSharpCode.SharpZipLib.Zip;


namespace Keyczar.Util
{
    /// <summary>
    /// Zip file that doesn't close the underlying stream when disposed
    /// </summary>
    public class NondestructiveZipFile : ZipOutputStream 
    {
        private MemoryStream _stream;
        public static NondestructiveZipFile Create()
        {
            var stream = new MemoryStream();
            var zip = new NondestructiveZipFile(stream);
            zip._stream = stream;
            
            return zip;
        }
        private NondestructiveZipFile(Stream stream) : base(stream)
        {
            base.IsStreamOwner = false;
        }

        public void Save(Stream stream)
        {
            _stream.Position = 0;
            _stream.CopyTo(stream);
        }
    }
}
