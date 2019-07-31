
using Keyczar.Util;

namespace Keyczar
{
    public static class KeyczarConst
    {
        /// <summary>
        /// Keyczar format version
        /// </summary>
        public static readonly byte FormatVersion = 0;

        /// <summary>
        /// Key hash length
        /// </summary>
        public static readonly int KeyHashLength = 4;

        /// <summary>
        /// The meta data format
        /// </summary>
        public static readonly string MetaDataFormat = "1";

        /// <summary>
        /// Keyczar format version bytes for header
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        public static readonly ReadOnlyArray<byte> FormatBytes = ReadOnlyArray.Create(FormatVersion);
        
        /// <summary>
        /// Full keyczar format header length
        /// </summary>
        public static readonly int HeaderLength = FormatBytes.Length + KeyHashLength;
    }
}