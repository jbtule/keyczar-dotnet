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
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using Keyczar;
using Keyczar.Unofficial;
using Newtonsoft.Json;

namespace Keyczar
{
    /// <summary>
    /// Metadata for a keyset
    /// </summary>
    public class KeyMetadata
    {
        private KeyType _keyType;

        /// <summary>
        /// Reads the specified meta data.
        /// </summary>
        /// <param name="metadata">The meta data.</param>
        /// <returns></returns>
        public static KeyMetadata Read(string metadata)
        {
            return JsonConvert.DeserializeObject<KeyMetadata>(metadata);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata"/> class.
        /// </summary>
        public KeyMetadata()
        {
            Name = String.Empty;
            Versions = new List<KeyVersion>();
            Format = Keyczar.MetaDataFormat;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata" /> class.
        /// </summary>
        /// <param name="officialMetaDataKeyType">Uses official meta data, requires specifying key, if null uses new metadata format</param>
        public KeyMetadata(KeyType officialMetaDataKeyType)
        {
            Name = String.Empty;
            Versions = new List<KeyVersion>();
            Format = Keyczar.MetaDataFormat;

            if (officialMetaDataKeyType != null)
            {
                Format = OfficialKeyMetadata.MetaDataFormat;
                OriginallyOfficial = true;
#pragma warning disable 618
                KeyType = officialMetaDataKeyType;
#pragma warning restore 618
            }
        }


       [OnDeserialized]
       internal void OnDeserializedMethod(StreamingContext context) {
           if (Format == OfficialKeyMetadata.MetaDataFormat) //Version 0
           {
               OriginallyOfficial = true;
#pragma warning disable 612,618
               var keyType = KeyType;
#pragma warning restore 612,618
               if (keyType == null)
               {
                   throw  new InvalidKeySetException("Official KeySet needs KeyType set");
               }

               Kind = keyType.Kind;
               foreach (var version in Versions)
               {
                   version.KeyType = keyType;
               }
           }
        }
    

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata"/> class.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public KeyMetadata(KeyMetadata metadata)
        {
            Name = metadata.Name ?? String.Empty;
            Purpose = metadata.Purpose;
            Encrypted = metadata.Encrypted;
            Versions = metadata.Versions.Select(it => new KeyVersion(it)).ToList();
#pragma warning disable 618
            KeyType = metadata?.KeyType;
#pragma warning restore 618
            OriginallyOfficial = metadata.OriginallyOfficial;
            Kind = metadata.Kind;

            Format = Keyczar.MetaDataFormat;

        }

        [JsonIgnore]
        public bool OriginallyOfficial { get; set; }

        /// <summary>
        /// Gets or sets the metadata format version.
        /// </summary>
        /// <value>
        /// The format version.
        /// </value>
        [DefaultValue(OfficialKeyMetadata.MetaDataFormat)]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore, 
            DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
        public string Format { get; set; }


        /// <summary>
        /// Gets or sets the kind.
        /// </summary>
        /// <value>
        /// The kind.
        /// </value>
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public KeyKind Kind { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the purpose.
        /// </summary>
        /// <value>The purpose.</value>
        public KeyPurpose Purpose { get; set; }

        /// <summary>
        /// Gets or sets the key type. for version 0 format only
        /// </summary>
        /// <value>The key type.</value>
        [Obsolete("Use DefaultKeyType or GetKeyType Instead")]
        [JsonProperty(PropertyName = "Type", NullValueHandling = NullValueHandling.Ignore)]
        public KeyType KeyType { get; set; }


        /// <summary>
        /// Gets the default type of the key.
        /// </summary>
        /// <value>
        /// The default type of the key.
        /// </value>
        /// <exception cref="InvalidKeySetException">No default type for public keysets</exception>

        [JsonIgnore]
        public KeyType DefaultKeyType
        {
            get
            {
                if (KeyKind.IsNullOrEmpty(Kind))
                {
#pragma warning disable 612,618
                    return KeyType;
#pragma warning restore 612,618
                }else if (Kind == KeyKind.Symmetric && Purpose == KeyPurpose.DecryptAndEncrypt)
                {
                    if (OriginallyOfficial)
                    {
                        return KeyType.Aes;
                    }
                    else
                    {
                        return UnofficialKeyType.AesAead;
                    }
                }
                else if (Kind == KeyKind.Symmetric && Purpose == KeyPurpose.SignAndVerify)
                {
                    if (OriginallyOfficial)
                    {
                        return KeyType.HmacSha1;
                    }
                    else
                    {
                        return UnofficialKeyType.HmacSha2;
                    }
                }
                else if (Kind == KeyKind.Private && Purpose == KeyPurpose.DecryptAndEncrypt)
                {
                    return KeyType.RsaPriv;
                }
                else if (Kind == KeyKind.Private && Purpose == KeyPurpose.SignAndVerify)
                {
                    if (OriginallyOfficial)
                    {
                        return KeyType.DsaPriv;
                    }
                    else
                    {
                        return UnofficialKeyType.RSAPrivSign;
                    }
                }
                else
                {
                    throw new InvalidKeySetException("No default type for public keysets");
                }
            }
        }

        /// <summary>
        /// Gets the type of the key.
        /// </summary>
        /// <param name="version">The version.</param>
        /// <returns></returns>
        public KeyType GetKeyType(int version)
        {
           
#pragma warning disable 612,618
            return Versions.Where(it => it.VersionNumber == version).Select(it => it.KeyType).FirstOrDefault() ?? KeyType;
#pragma warning restore 612,618
        }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="KeyMetadata"/> is encrypted.
        /// </summary>
        /// <value><c>true</c> if encrypted; otherwise, <c>false</c>.</value>
        public bool Encrypted { get; set; }

        /// <summary>
        /// Gets or sets the versions.
        /// </summary>
        /// <value>The versions.</value>
        public IList<KeyVersion> Versions { get; internal set; }

        public bool ValidOfficial()
        {

            return (!Versions.Any()
#pragma warning disable 618
                   && !(KeyType?.Unofficial ?? false))
#pragma warning restore 618
                   || (Versions.All(it=>!it.KeyType.Unofficial)
                   && Versions.Select(it => it.KeyType).Distinct().Count() == 1);
        }

        public KeyType OfficialKeyType()
        {
#pragma warning disable 618
            return (KeyType != null)
                ? KeyType
#pragma warning restore 618
                : Versions.Any()
                    ? Versions.Select(it => it.KeyType).Distinct().Single()
                    : DefaultKeyType;
        }
    }
}