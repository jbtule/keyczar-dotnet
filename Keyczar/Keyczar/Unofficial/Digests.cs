using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar.Util;

namespace Keyczar.Unofficial
{
    public class DigestAlg: StringType
    {
        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="DigestAlg"/>.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The result of the conversion.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Constructor is alternative")]
        public static implicit operator DigestAlg(string identifier) 
            => String.IsNullOrWhiteSpace(identifier) 
                ? null 
                : new DigestAlg(identifier);


        /// <summary>
        /// The sha1 digest
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly DigestAlg Sha1 = "SHA1";

        /// <summary>
        /// The sha224 digest
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly DigestAlg Sha224 = "SHA224";

        /// <summary>
        /// The sha256 digest
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly DigestAlg Sha256 = "SHA256";

        /// <summary>
        /// The sha384 digest
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly DigestAlg Sha384 = "SHA384";

        /// <summary>
        /// The sha512 digest
        /// </summary>
       [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly DigestAlg Sha512 = "SHA512";

        public DigestAlg(string identifier) : base(identifier)
        {
        }
    }
}
