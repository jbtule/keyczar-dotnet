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
using Ionic.Zip;

namespace Keyczar.Util
{
    /// <summary>
    /// Zip file that doesn't close the underlying stream when disposed
    /// </summary>
    public class NondestructiveZipFile : ZipFile
    {
        /// <summary>
        /// Disposes any managed resources, if the flag is set, then marks the
        /// instance disposed.  This method is typically not called explicitly from
        /// application code.
        /// </summary>
        /// <param name="disposeManagedResources">indicates whether the method should dispose streams or not.</param>
        /// <remarks>
        /// Applications should call <see cref="M:Ionic.Zip.ZipFile.Dispose">the no-arg Dispose method</see>.
        /// </remarks>
        protected override void Dispose(bool disposeManagedResources)
        {
            base.Dispose(false);
        }
    }
}