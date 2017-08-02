/*  Copyright 2013 James Tuley (jay+code@tuley.name)
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

namespace Keyczar.Unofficial
{
    /// <summary>
    /// Place to find Unofficial KeyType identifiers
    /// </summary>
    public static class UnofficialKeyType
    {
        /// <summary>
        /// Unofficial type AES Authenticated Encryption with Associated Data
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType AesAead = "C#_AES_AEAD";

        /// <summary>
        /// The Unofficial RSA priv sign
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType RSAPrivSign =
                "C#_RSA_SIGN_PRIV";

        /// <summary>
        /// The Unofficial RSA pub sign
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType RSAPubSign =
                "C#_RSA_SIGN_PUB";

        static UnofficialKeyType()
        {
            //Unofficial
            AesAead.KeySizes<AesAeadKey>(256, 192, 128).IsUnofficial().DefineSpec();
            RSAPrivSign.KeySizes<RsaPrivateSignKey>(2048, 3072, 4096, 1024).IsAsymmetric().IsUnofficial().DefineSpec();
            RSAPubSign.KeySizes<RsaPublicSignKey>(2048, 3072, 4096, 1024).IsAsymmetric().IsUnofficial().DefineSpec();
        }
    }
}