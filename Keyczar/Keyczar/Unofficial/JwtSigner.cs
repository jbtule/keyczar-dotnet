using System;
using System.IO;
using System.Text;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Utilities.Encoders;

namespace Keyczar.Unofficial
{
    public class JwtSigner:JwtVerifier
    {
        private JwtSignerHelper _signer;

        public JwtSigner(IKeySet keySet) : base(keySet)
        {
            _signer = new JwtSignerHelper(keySet, this);
        }

        public string SignCompact(JObject payload)
        {
            return _signer.SignCompact(payload);
        }
        
        public string SignCompact(byte[] payload)
        {
            return _signer.SignCompact(payload);
        }

        protected override void Dispose(bool disposing)
        {
            _signer = _signer.SafeDispose();
            base.Dispose(disposing);
        }

        protected class JwtSignerHelper : Signer
        {
            private KeyczarBase _parent;

            public JwtSignerHelper(IKeySet keySet, KeyczarBase parent)
                : base(keySet)
            {
                _parent = parent;
            }

            public override KeyczarConfig Config
            {
                get => _parent.Config;
                set { }
            }
            

            protected override void PrefixDataSign(HashingStream signingStream, object extra)
            {
            }
            
            protected override void PostfixDataSign(HashingStream signingStream, object extra)
            {
            }

            protected override void PrefixDataVerify(VerifyingStream verifyingStream, object extra)
            {
            }
            
            protected override void PostfixDataVerify(VerifyingStream verifyingStream, object extra)
            {
            }

            public string SignCompact(byte[] payload)
            {
                var key = this.GetPrimaryKey();

                var alg = Jwt.AlgForKey(key);
                if (alg == null)
                {
                    throw new InvalidKeyTypeException("Invalid Key Parameters For JWT");
                }
                
                var header = new JwtHeader
                {
                    typ = "JWT",
                    alg = alg?.ToString(),
                    kid = WebBase64.FromBytes(key.GetKeyHash())

                };

                   
                var stringHeader = JsonConvert.SerializeObject(header);

                var encodedHeader = Jwt.EncodeToBase64(stringHeader);
                
                var encodedPayload = WebBase64.FromBytes(payload);

                
                var input =Encoding.UTF8.GetBytes($"{encodedHeader}.{encodedPayload}");
                using (var outStream = new MemoryStream())
                using (var memStream = new MemoryStream(input))
                {
                    Sign(memStream, outStream, null, null, input, -1);
                    return Encoding.UTF8.GetString(outStream.ToArray());
                }

            }

            public string SignCompact(JObject payload)
            {
             
                var stringPayload = JsonConvert.SerializeObject(payload);

                return SignCompact(Encoding.UTF8.GetBytes(stringPayload));

            }
            
            
            
            protected override void PadSignature(byte[] signature, Stream outputStream, object extra)
            {                
                var input = (byte[]) extra;
                outputStream.Write(input,0,input.Length);
                outputStream.Write(Encoding.UTF8.GetBytes("."),0,1);
                var b64Sig = WebBase64.FromBytes(signature);
                var sig = Encoding.UTF8.GetBytes(b64Sig.ToString());
                outputStream.Write(sig, 0, sig.Length);
                
            }

        }
    }
}