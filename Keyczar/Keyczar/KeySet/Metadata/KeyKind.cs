using System.ComponentModel;

namespace Keyczar
{
    /// <summary>
    /// Key Kind
    /// </summary>'
    [ImmutableObject(true)]
    public class KeyKind : Util.StringType
    {
        /// <summary>
        /// symmetric
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly KeyKind Symmetric = "SYMMETRIC";

        /// <summary>
        /// private
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly KeyKind Private = "PRIVATE";

        /// <summary>
        /// The public
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly KeyKind Public = "PUBLIC";

        /// <summary>
        ///  the Kind of Keys.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Constructor is alternative")]
        public static  implicit operator KeyKind(string identifier)
        {
            return new KeyKind(identifier);
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="KeyKind" /> class.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        public KeyKind(string identifier)
            : base(identifier)
        {
        }

    }
}