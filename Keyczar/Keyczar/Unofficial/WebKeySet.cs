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


using System.Globalization;
using System.Net;
using Newtonsoft.Json;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Access and Public Key Set or Encrypted KeySet from the web.
    /// </summary>
    public class WebKeySet : IKeySet
    {
    

        /// <summary>
        /// Initializes a new instance of the <see cref="WebKeySet" /> class.
        /// </summary>
        /// <param name="webUrl">The web URL.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings", MessageId = "0#", Justification = "Uri is way to inconvenient for a simple web address")]
        public WebKeySet(string webUrl)
        {
            WebClient = new WebClient { BaseAddress = webUrl };
        }

        /// <summary>
        /// Gets the web client.
        /// </summary>
        /// <value>
        /// The web client.
        /// </value>
        public WebClient WebClient { get; private set; }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        /// <value>
        /// The metadata.
        /// </value>
        public KeyMetadata Metadata
        {
            get { 
                var meta = WebClient.DownloadString("meta");
                return JsonConvert.DeserializeObject<KeyMetadata>(meta);
            }
        }


        /// <summary>
        /// Gets the binary data that the key is stored in.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public byte[] GetKeyData(int version)
        {
            var data = WebClient.DownloadData(version.ToString(CultureInfo.InvariantCulture));
            return data;
        }

    }
}
