using System.ComponentModel;
using Keyczar.Util;

namespace Keyczar.Pbe
{
    /// <summary>
    /// Type of cipher to use for encrypting keys with password.
    /// </summary>
    [ImmutableObject(true)]
    public class PbeKeyType : StringType
    {
        /// <summary>
        /// AES 128
        /// </summary>
        public static readonly PbeKeyType AES_128 = "AES128";


        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="PbeKeyType"/>.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator PbeKeyType(string identifier)
        {
            return new PbeKeyType(identifier);
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="PbeKeyType"/> class.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        public PbeKeyType(string identifier) : base(identifier)
        {
        }
    }
}