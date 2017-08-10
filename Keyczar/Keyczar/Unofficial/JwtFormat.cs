using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Keyczar.Unofficial
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public class JwtHeader
    {
        public string alg { get; set; }
        public string kid { get; set; }
        public string typ { get; set; }
    }

    internal static class JwtUtil
    {
        internal static string DecodeToJsonString(string encoded)
        {
            var base64 = (WebBase64) encoded;
            return Encoding.UTF8.GetString(base64.ToBytes());
        }
        
        internal static string EncodeToBase64(string jsontext)
        {
            var rawBytes = Encoding.UTF8.GetBytes(jsontext);
            return WebBase64.FromBytes(rawBytes).ToString();
        }
        
        internal static bool AlgVerifier(string alg, Key key)
        {
            var priv = key as Unofficial.RsaPrivateSignKey;
            var pub = key as Unofficial.RsaPublicSignKey;

            if (priv != null || pub != null)
            {
                var rsa = pub ?? priv?.PublicKey; 
                switch (alg)
                {
                    case "PS256":
                        return rsa.Digest == DigestAlg.Sha256;
                    case "PS384":
                        return rsa.Digest == DigestAlg.Sha384;
                    case "PS512":
                        return rsa.Digest == DigestAlg.Sha512;

                }
            }
            return false;
        }
        
        internal static string AlgForKey(Key key)
        {
            switch(key){
                 case Unofficial.RsaPrivateSignKey k when k.Digest == DigestAlg.Sha256:
                     return "PS256";
                case Unofficial.RsaPublicSignKey k when k.Digest == DigestAlg.Sha384:
                    return "PS384";
                case Unofficial.RsaPublicSignKey k when k.Digest == DigestAlg.Sha512:
                    return "PS512";
                case Unofficial.HmacSha2Key k when k.Digest == DigestAlg.Sha256:
                    return "HS256";
                case Unofficial.HmacSha2Key k when k.Digest == DigestAlg.Sha384:
                    return "HS384";
                case Unofficial.HmacSha2Key k when k.Digest == DigestAlg.Sha512:
                    return "HS512";
                default:
                    return null;
            }
        }
    }
}