using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keyczar.Unofficial
{
    public class JwtVerifier:KeyczarBase
    {
        private HelperAttachedJTWVerifier _verifier;

        public bool VerifyCompact(string input)
        {
            return _verifier.VerifyCompact(input, out JObject payload);
        }
        
        public bool VerifyCompact(string input, out JObject payload)
        {
            return _verifier.VerifyCompact(input, out payload);
        }
        
        protected override void Dispose(bool disposing)
        {
            _verifier = _verifier.SafeDispose();
            base.Dispose(disposing);
        }
        
        /// <summary>
        /// Initializes a new instance of the <see cref="AttachedSigner" /> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        /// <exception cref="InvalidKeySetException">This key set can not be used for verifying signatures.</exception>
        public JwtVerifier(IKeySet keySet) : base(keySet)
        {
            if (keySet.Metadata.Purpose != KeyPurpose.Verify
                && keySet.Metadata.Purpose != KeyPurpose.SignAndVerify)
            {
                throw new InvalidKeySetException("This key set can not be used for verifying signatures.");
            }
            _verifier = new HelperAttachedJTWVerifier(keySet, this);
        }

        protected class HelperAttachedJTWVerifier : Verifier
        {
            private KeyczarBase _parent;

            public HelperAttachedJTWVerifier(IKeySet keySet, KeyczarBase parent) : base(keySet)
            {
                _parent = parent;
            }

            public override KeyczarConfig Config
            {
                get => _parent.Config;
                set { }
            }

            public bool VerifyCompact(string input, out JObject payload)
            {

                var pieces = input.Split('.');

                if (pieces.Length != 3)
                {
                    throw new InvalidCryptoDataException("Not a JWT Compact Token");
                }

                var message = Encoding.UTF8.GetBytes(string.Join(".", pieces.Take(2)));


                var verify = Verify(message, Encoding.UTF8.GetBytes(input));

                payload = verify
                    ? JObject.Parse(Jwt.DecodeToJsonString(pieces[1]))
                    : null;
                return verify;

            }

            protected override void PrefixDataVerify(VerifyingStream verifyingStream, object extra)
            {

            }

            /// <summary>
            /// Posts the fix data before verifying.
            /// </summary>
            /// <param name="verifyingStream">The verifying stream.</param>
            /// <param name="extra">The extra data passed by postFixData</param>
            protected override void PostfixDataVerify(VerifyingStream verifyingStream, object extra)
            {

            }


            /// <summary>
            /// Gets the keys.
            /// </summary>
            /// <param name="signature">The signature.</param>
            /// <param name="trimmedSignature">The trimmed signature.</param>
            /// <returns></returns>
            protected override IEnumerable<IVerifierKey> GetKeys(byte[] signature, out byte[] trimmedSignature)
            {
                return Jwt.VerifierKeys(this, signature, out trimmedSignature);
            }
        }

    }
}