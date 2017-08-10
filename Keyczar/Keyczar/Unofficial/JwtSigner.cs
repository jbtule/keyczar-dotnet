using System;
using System.IO;
using System.Text;
using Keyczar.Crypto.Streams;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Utilities.Encoders;

namespace Keyczar.Unofficial
{
    public class JwtSigner:KeyczarBase
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
            
            
            
            
            protected override void PrefixDataVerify(VerifyingStream verifyingStream, object extra)
            {

            }

            protected override void PostfixDataVerify(VerifyingStream verifyingStream, object extra)
            {

            }
            
          
            public string SignCompact(JObject payload)
            {
                var key = this.GetPrimaryKey();

                var header = new JwtHeader
                {
                    typ = "JWT",
                    alg = JwtUtil.AlgForKey(key),
                    kid = WebBase64.FromBytes(key.GetKeyHash())

                };
                
                var stringHeader = JsonConvert.SerializeObject(header);

                var encodedHeader = JwtUtil.EncodeToBase64(stringHeader);
                
                var stringPayload = JsonConvert.SerializeObject(payload);

                var encodedPayload = JwtUtil.EncodeToBase64(stringPayload);

                var input =Encoding.UTF8.GetBytes(encodedHeader + $"." + encodedPayload);
                using (var outStream = new MemoryStream())
                using (var memStream = new MemoryStream(input))
                {
                    Sign(memStream, outStream, null, null, input, input.Length);
                    return Encoding.UTF8.GetString(outStream.ToArray());
                }
            }
            
            protected override void PadSignature(byte[] signature, Stream outputStream, object extra)
            {
                var input = (byte[]) extra;
                outputStream.Write(input,0,input.Length);

                var sig = Encoding.UTF8.GetBytes(WebBase64.FromBytes(signature).ToString());
                outputStream.Write(sig, 0, sig.Length);
                
            }

        }
    }
}