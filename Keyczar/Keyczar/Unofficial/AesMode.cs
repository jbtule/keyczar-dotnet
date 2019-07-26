using System;
using Keyczar.Util;

namespace Keyczar.Unofficial
{
    public class AesMode: StringType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Constructor is alternative")]
        public static implicit operator AesMode(string identifier) 
            => String.IsNullOrWhiteSpace(identifier) 
                ? null 
                : new AesMode(identifier);
        
        public AesMode(string identifier) : base(identifier)
        {
        }
        
        
        public static readonly AesMode Cbc = "CBC";
        
#pragma warning disable 618
        public static readonly AesMode Gcm = AesAeadKey.GcmMode;
#pragma warning restore 618
    }
}