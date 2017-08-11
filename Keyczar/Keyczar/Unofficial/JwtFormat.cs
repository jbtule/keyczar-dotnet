using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using Keyczar.Crypto;
using Keyczar.Util;
using Newtonsoft.Json;

namespace Keyczar.Unofficial
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public class JwtHeader
    {
        public string alg { get; set; }
        public string kid { get; set; }
        public string typ { get; set; }
    }
    
    
    public class JwtAlg : StringType
    {     
        public static implicit operator JwtAlg(string identifier) 
            => String.IsNullOrWhiteSpace(identifier) 
                ? null 
                : new JwtAlg(identifier);

        
        public JwtAlg(string identifier) : base(identifier)
        {
        }

        public static readonly JwtAlg RsaPssSha256 = "PS256";
        public static readonly JwtAlg RsaPssSha384 = "PS384";
        public static readonly JwtAlg RsaPssSha512 = "PS512";
        
        public static readonly JwtAlg RsaPkcs15Sha256 = "RS256";
        public static readonly JwtAlg RsaPkcs15Sha384 = "RS384";
        public static readonly JwtAlg RsaPkcs15Sha512 = "RS512";

        public static readonly JwtAlg HmacSha256 = "HS256";
        public static readonly JwtAlg HmacSha384 = "HS384";
        public static readonly JwtAlg HmacSha512 = "HS512";
    }
    

    public static class Jwt
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
        
        public static bool IsValidAlg(JwtAlg alg, Key key)
        {
            return alg != null && alg == AlgForKey(key);
        }
        
        internal static IEnumerable<IVerifierKey> VerifierKeys(KeyczarBase keyczar, byte[] token, out byte[] trimmedSignature)
        {
            var input = Encoding.UTF8.GetString(token);
            var pieces = input.Split('.');
            var sig = (WebBase64) pieces.Last();
            trimmedSignature = sig.ToBytes();

            var header = JsonConvert.DeserializeObject<JwtHeader>(
                Jwt.DecodeToJsonString(pieces.First()));

            if (header.typ != "JWT")
            {
                return Enumerable.Empty<IVerifierKey>();
            }

            byte[] kid = null;

            try //try to interpret kid has key hash.
            {
                var kidB64 = (WebBase64) header.kid;
                kid = kidB64.ToBytes();
            }
            catch{}
            
            
            if (kid == null || kid.Length != KeyczarConst.KeyHashLength)
            {
                return keyczar.GetAllKeys()
                    .Where(it => Jwt.IsValidAlg(header.alg, it))
                    .OfType<IVerifierKey>();
            }
            
            return keyczar.GetKey(kid)
                .Where(it => Jwt.IsValidAlg(header.alg, it))
                .OfType<IVerifierKey>();
        }
    
        
        public static JwtAlg AlgForKey(Key key)
        {
            var pubKey = (key as IRsaPrivateKey)?.PublicKey as Key;
            
            switch(pubKey ?? key){
                case Unofficial.RsaPublicSignPssKey k when k.Digest == DigestAlg.Sha256:
                     return JwtAlg.RsaPssSha256;
                case Unofficial.RsaPublicSignPssKey k when k.Digest == DigestAlg.Sha384:
                    return JwtAlg.RsaPssSha384;
                case Unofficial.RsaPublicSignPssKey k when k.Digest == DigestAlg.Sha512:
                    return JwtAlg.RsaPssSha512;
                case Unofficial.RsaPublicSignPkcs15Key k when k.Digest == DigestAlg.Sha256:
                    return JwtAlg.RsaPkcs15Sha256;
                case Unofficial.RsaPublicSignPkcs15Key k when k.Digest == DigestAlg.Sha384:
                    return JwtAlg.RsaPkcs15Sha384;
                case Unofficial.RsaPublicSignPkcs15Key k when k.Digest == DigestAlg.Sha512:
                    return JwtAlg.RsaPkcs15Sha512;
                case Unofficial.HmacSha2Key k when k.Digest == DigestAlg.Sha256:
                    return JwtAlg.HmacSha256;
                case Unofficial.HmacSha2Key k when k.Digest == DigestAlg.Sha384:
                    return JwtAlg.HmacSha384;
                case Unofficial.HmacSha2Key k when k.Digest == DigestAlg.Sha512:
                    return JwtAlg.HmacSha512;
                default:
                    return null;
            }
        }
    }
}