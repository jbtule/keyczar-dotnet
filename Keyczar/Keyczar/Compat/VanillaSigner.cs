/*
*  Copyright 2012 James Tuley (jay+code@tuley.name)
* 
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
* 
*      http://www.apache.org/licenses/LICENSE-2.0
* 
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*/

using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;

namespace Keyczar.Compat
{   
    /// <summary>
    /// Plain old signing with plain old signature
    /// </summary>
    public class VanillaSigner:Signer
    {

        /// <summary>
        /// Initializes a new instance of the <see cref="VanillaSigner"/> class.
        /// </summary>
        /// <param name="keySetLocation">The key set location.</param>
        public VanillaSigner(string keySetLocation) : this(new KeySet(keySetLocation))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="VanillaSigner"/> class.
        /// </summary>
        /// <param name="keySet">The key set.</param>
        public VanillaSigner(IKeySet keySet)
        : base(keySet)
        {
        }

        /// <summary>
        /// Prefixes the data then signs it.
        /// </summary>
        /// <param name="signingStream">The signing stream.</param>
        /// <param name="extra">The extra data passed by prefixData.</param>
        protected override void PrefixDataSign(HashingStream signingStream, object extra)
        {
            
        }

        /// <summary>
        /// Postfixes the data then signs it.
        /// </summary>
        /// <param name="signingStream">The signing stream.</param>
        /// <param name="extra">The extra data passed by postfixData.</param>
        protected override void PostfixDataSign(HashingStream signingStream, object extra)
        {
           
        }

        /// <summary>
        /// Prefixes the data before verifying.
        /// </summary>
        /// <param name="verifyingStream">The verifying stream.</param>
        /// <param name="extra">The extra data passed by prefixData</param>
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
        /// Pads the signature with extra data.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <param name="outputStream">The padded signature.</param>
        /// <param name="extra">The extra data passed by sigData.</param>
        /// <returns></returns>
        protected override void PadSignature(byte[] signature, Stream outputStream,  object extra)
        {
            outputStream.Write(signature,0,signature.Length);
        }

        /// <summary>
        /// Gets the keys.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <param name="trimmedSignature">The trimmed sig.</param>
        /// <returns></returns>
        protected override IEnumerable<IVerifierKey> GetKeys(byte[] signature, out byte[] trimmedSignature)
        {
            trimmedSignature = signature;
            return GetAllKeys().OfType<IVerifierKey>();
        }
    }

}
