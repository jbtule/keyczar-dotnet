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
using System.Globalization;
using System.IO;
using System.Linq;
using Keyczar.Util;

using Newtonsoft.Json;

namespace Keyczar
{
    /// <summary>
    /// Writes a keyset using the standard storage format
    /// </summary>
    public class KeySetWriter:IKeySetWriter
    {
        private readonly string _location;
        private readonly bool _overwrite;
        private List<string> _filePaths = new List<string> ();
        private List<Exception> _exceptions = new List<Exception>();
        private bool success = true;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeySetWriter"/> class.
        /// </summary>
        /// <param name="location">The location.</param>
        /// <param name="overwrite">if set to <c>true</c> [overwrite].</param>
        public KeySetWriter(string location, bool overwrite =false)
        {
            _location = location;
            _overwrite = overwrite;
        }

        private void CreateDir()
        {
            if (!Directory.Exists(_location))
                Directory.CreateDirectory(_location);
        }

        /// <summary>
        /// Writes the specified key data.
        /// </summary>
        /// <param name="keyData">The key data.</param>
        /// <param name="version">The version.</param>
        public void Write(byte[] keyData, int version)
        {
            CreateDir();
            var file = Path.Combine(_location, version.ToString(CultureInfo.InvariantCulture)+".temp");
            if (!_overwrite && File.Exists(file))
            {
                success = false;
                return;
            } 
            _filePaths.Add(file);
            try
            {
                using (var stream = File.OpenWrite(file))
                using (var writer = new BinaryWriter(stream))
                {
                    writer.Write(keyData);
                }
            }
            catch(Exception ex)
            {
                _exceptions.Add(ex);
                success = false;
            }

        }

        /// <summary>
        /// Writes the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="version">The version.</param>
        public void Write(Key key, int version)
        {
            Write(Keyczar.DefaultEncoding.GetBytes(JsonConvert.SerializeObject(key)),version);
        }

        /// <summary>
        /// Writes the specified metadata.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public void Write(KeyMetadata metadata)
        {
            CreateDir();
            var file = Path.Combine(_location, "meta.temp");
            if (!_overwrite && File.Exists(file))
            {
                success = false;
                return;
            }
            try
            {
                _filePaths.Add(file);
                using (var stream = File.OpenWrite(file))
                using (var writer = new StreamWriter(stream))
                {
                    writer.Write(JsonConvert.SerializeObject(metadata));
                }
            }
            catch(Exception ex)
            {
                _exceptions.Add(ex);
                success = false;
            }

            
        }

        /// <summary>
        /// Finishes this writing of the key.
        /// </summary>
        /// <returns></returns>
        public bool Finish()
        {
            if (success)
            {
                foreach (var path in _filePaths)
                {
                    var newPath = Path.Combine(Path.GetDirectoryName(path),
					                           Path.GetFileNameWithoutExtension(path));
                    File.Delete(newPath);
                    File.Move(path, newPath);
                }

            }else
            {
                foreach (var path in _filePaths)
                {
                    File.Delete(path);
                }
            }

            Exception newEx =null;
            if(_exceptions.Any())
                newEx = new AggregateException(_exceptions);

            _filePaths.Clear();
            _exceptions.Clear();

            if (newEx != null)
                throw newEx;
            
            return success;
        }
    }
}