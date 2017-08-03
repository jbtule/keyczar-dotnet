using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Keyczar
{
    internal class OfficialKeyVersion
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVersion"/> class.
        /// </summary>
        public OfficialKeyVersion()
        {
            Status = KeyStatus.Active;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVersion"/> class.
        /// </summary>
        /// <param name="keyVersion">The key version.</param>
        public OfficialKeyVersion(KeyVersion keyVersion)
        {
            VersionNumber = keyVersion.VersionNumber;
            Exportable = keyVersion.Exportable;
            Status = keyVersion.Status;
        }

        /// <summary>
        /// Gets or sets the version number.
        /// </summary>
        /// <value>The version number.</value>
        public int VersionNumber { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="KeyVersion"/> is exportable.
        /// </summary>
        /// <value><c>true</c> if exportable; otherwise, <c>false</c>.</value>
        public bool Exportable { get; set; }

        /// <summary>
        /// Gets or sets the status.
        /// </summary>
        /// <value>The status.</value>
        public KeyStatus Status { get; set; }

    }

}
