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
        
#pragma warning disable 612
        public static readonly PaddingAlg Pss = RsaPublicSignKey.PssPadding;
#pragma warning restore 612
    }
}