using System.ComponentModel;
using Keyczar.Util;

namespace Keyczar.Pbe
{
    /// <summary>
    /// Type of Hash to use for the Password Derived Bytes
    /// </summary>
    [ImmutableObject(true)]
    public class PbeHashType : StringType
    {
        /// <summary>
        /// Hmac Sha1
        /// </summary>
        public static readonly PbeHashType HmacSha1 = "HMAC_SHA1";
        /// <summary>
        /// Hmac Sha256
        /// </summary>
        public static readonly PbeHashType HmacSha256 = "HMAC_SHA256";

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="PbeHashType"/>.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator PbeHashType(string identifier)
        {
            return new PbeHashType(identifier);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PbeHashType"/> class.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        public PbeHashType(string identifier) : base(identifier)
        {
        }
    }
}