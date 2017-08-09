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
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Access and Public Key Set or Encrypted KeySet from the web.
    /// </summary>
    public class WebKeySet : IRootProviderKeySet
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WebKeySet" /> class.
        /// </summary>
        /// <param name="webUrl">The web URL.</param>
        /// <param name="allowNonSslUrl">Allow non https urls (less security)</param>
        /// <exception cref="System.ArgumentException">https urls only;webUrl</exception>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings",
            MessageId = "0#", Justification = "Uri is way to inconvenient for a simple web address")]
        public WebKeySet(string webUrl, bool allowNonSslUrl = false)
        {
            if (!allowNonSslUrl && !webUrl.StartsWith("https:", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new ArgumentException("https urls only","webUrl");
            }

            WebClient = new WebClient {BaseAddress = webUrl};
        }
        /// <summary>
        /// Adds the thumbprint to identify valid self signed certificates.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        public static void AddSelfSignedThumbprint(string thumbprint)
        {
            thumbprint = thumbprint.Replace(":", "");
            thumbprint = thumbprint.Replace(" ", ""); 
            thumbprint = thumbprint.ToUpperInvariant();
            if (SelfSignedThumbprints.Count == 0)
            {
                ServicePointManager.ServerCertificateValidationCallback += CertificateValidationCallback;
            }
            SelfSignedThumbprints.Add(thumbprint);
        }

        /// <summary>
        /// Removes thumbprint to identify valid self signed certificates.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        public static void RemoveSelfSignedThumbprint(string thumbprint)
        {
            thumbprint = thumbprint.Replace(":", "");
            thumbprint = thumbprint.Replace(" ", "");
            thumbprint = thumbprint.ToUpperInvariant();
            SelfSignedThumbprints.Remove(thumbprint);
            if (SelfSignedThumbprints.Count == 0)
            {
// ReSharper disable DelegateSubtraction
                ServicePointManager.ServerCertificateValidationCallback -= CertificateValidationCallback;
// ReSharper restore DelegateSubtraction
            }
        }


        /// <summary>
        /// The self signed thumbprints
        /// </summary>
        private static readonly HashSet<string> SelfSignedThumbprints = new HashSet<string>();



        private static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            if (sslpolicyerrors == SslPolicyErrors.None)
                return true;
            if (sslpolicyerrors == SslPolicyErrors.RemoteCertificateChainErrors)
            {
                var cert = certificate as X509Certificate2;
                if (cert != null)
                {
                    return SelfSignedThumbprints.Contains(cert.Thumbprint);
                }
            }
            return false;
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
            get
            {
                var meta = WebClient.DownloadString("meta");
                return JsonConvert.DeserializeObject<KeyMetadata>(meta);
            }
        }
        
        /// <summary>
        /// Config Options
        /// </summary>
        public KeyczarConfig Config { get; set; }


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

        #region IDisposable Support

        protected virtual void Dispose(bool disposing)
        {
          
        }

   
        // This code added to correctly implement the disposable pattern.
        public void Dispose() => Dispose(true);

        #endregion
    }
}