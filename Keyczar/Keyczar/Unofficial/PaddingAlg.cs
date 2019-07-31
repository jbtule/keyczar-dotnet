using System;
using Keyczar.Util;

namespace Keyczar.Unofficial
{
    public class PaddingAlg: StringType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Constructor is alternative")]
        public static implicit operator PaddingAlg(string identifier) 
            => String.IsNullOrWhiteSpace(identifier) 
                ? null 
                : new PaddingAlg(identifier);
        
        public PaddingAlg(string identifier) : base(identifier)
        {
        }
        
        public static readonly PaddingAlg Pss = "PSS";
        
        public static readonly PaddingAlg Pkcs15 = "PKCS15";
    }
}