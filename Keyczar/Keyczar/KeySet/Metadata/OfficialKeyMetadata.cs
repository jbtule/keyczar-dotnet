using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace Keyczar
{
    internal class OfficialKeyMetadata
    {
        internal const string MetaDataFormat = "0";
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata"/> class.
        /// </summary>
        public OfficialKeyMetadata()
        {
            Name = String.Empty;
            Versions = new List<OfficialKeyVersion>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMetadata"/> class.
        /// </summary>
        /// <param name="metadata">The metadata.</param>
        public OfficialKeyMetadata(KeyMetadata metadata)
        {
            Name = metadata.Name ?? String.Empty;
            Purpose = metadata.Purpose;
#pragma warning disable 618
            KeyType = metadata.KeyType;
#pragma warning restore 618

            if (!metadata.ValidOfficial())
            {
                throw new InvalidDataException("Official KeySet must only have one keytype");
            }

            KeyType = metadata.OfficialKeyType();
           

            Encrypted = metadata.Encrypted;
            Versions = metadata.Versions.Select(it => new OfficialKeyVersion(it)).ToList();
        }

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
        /// Gets or sets the key type.
        /// </summary>
        /// <value>The key type.</value>
        [JsonProperty("Type")]
        public KeyType KeyType { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="KeyMetadata"/> is encrypted.
        /// </summary>
        /// <value><c>true</c> if encrypted; otherwise, <c>false</c>.</value>
        public bool Encrypted { get; set; }

        /// <summary>
        /// Gets or sets the versions.
        /// </summary>
        /// <value>The versions.</value>
        public IList<OfficialKeyVersion> Versions { get; internal set; }
    }
}
