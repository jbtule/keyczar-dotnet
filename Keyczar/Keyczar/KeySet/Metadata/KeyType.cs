/*  Copyright 2012 James Tuley (jay+code@tuley.name)
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
using System.Collections.Generic;
using System.Linq;
using Keyczar.Crypto;

namespace Keyczar
{
    /// <summary>
    /// Metadata for Key Types
    /// </summary>
    public class KeyType : Util.StringType
    {

        /// <summary>
        /// Aes key
        /// </summary>
        public static readonly KeyType AES = "AES";
        /// <summary>
        /// Hmac Sha1 key
        /// </summary>
        public static readonly KeyType HMAC_SHA1 = "HMAC_SHA1";
        /// <summary>
        /// DSA Private Key
        /// </summary>
        public static readonly KeyType DSA_PRIV = "DSA_PRIV";
        /// <summary>
        /// Dsa Public key
        /// </summary>
        public static readonly KeyType DSA_PUB = "DSA_PUB";
        /// <summary>
        /// RSA private key
        /// </summary>
        public static readonly KeyType RSA_PRIV = "RSA_PRIV";
        /// <summary>
        /// Rsa public key type
        /// </summary>
        public static readonly KeyType RSA_PUB = "RSA_PUB";

        //Unofficial
        /// <summary>
        /// Unofficial type AES Authenticated Encryption with Associated Data
        /// </summary>
        public static readonly KeyType AES_AEAD = "C#_AES_AEAD";


        /// <summary>
        /// Get KeyType for the clr type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        public static KeyType ForType(Type type)
        {
            return _specs.Where(it => it.Value.Type == type).Select(it=>it.Key).FirstOrDefault();
        }

		protected static bool DefineSpec(KeyTypeSpec spec){
			if(_specs.ContainsKey(spec.Name.Identifier))
				return false;
			_specs.Add(spec.Name.Identifier, spec);
			return true;
		}

		static KeyType(){
			AES.KeySizes<AesKey>(128,192,256).DefineSpec();
			HMAC_SHA1.KeySizes<HmacSha1Key>(256).WithDigestSizes(20).DefineSpec();
			DSA_PRIV.KeySizes<DsaPrivateKey>(1024).WithDigestSizes(48).IsAsymmetric().DefineSpec();
			DSA_PUB.KeySizes<DsaPublicKey>(1024).WithDigestSizes(48).IsAsymmetric().DefineSpec();
			RSA_PRIV.KeySizes<RsaPrivateKey>(2048, 1024, 4096).WithDigestSizes(256, 128, 512).IsAsymmetric().DefineSpec();
			RSA_PUB.KeySizes<RsaPublicKey>(2048, 1024, 4096 ).WithDigestSizes(256, 128, 512).IsAsymmetric().DefineSpec();
			//Unofficial
			AES_AEAD.KeySizes<Unofficial.AesAeadKey>(256,192,128).IsUnofficial().DefineSpec();
		}

		private static readonly IDictionary<string, KeyTypeSpec> _specs = new Dictionary<string, KeyTypeSpec>();

        public KeyTypeSpec KeySizes<T>(params int[] keySizes) where T: Key
        {

            return new KeyTypeSpec
            {
                Name =  Identifier,
                Type = typeof(T),
                KeySizes = keySizes,
            };
        }

        public class KeyTypeSpec
        {
			internal KeyTypeSpec(){
			}

            public KeyType Name;
            public Type Type;
            public int[] KeySizes;
            public int[] DigestSizes = new int[]{0};
            public bool Unofficial;
            public bool Asymmetric;
            public KeyTypeSpec WithDigestSizes(params int[] sigSizes)
            {
                DigestSizes = sigSizes;
                return this;
            }
            public KeyTypeSpec IsUnofficial()
            {
                Unofficial = true;
                return this;
            }

            public KeyTypeSpec IsAsymmetric()
            {
                Asymmetric = true;
                return this;
            }

			public KeyType DefineSpec(){
				if(KeyType.DefineSpec(this))
					return Name;
				return null;
			}
        }

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="KeyType"/>.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator KeyType(string identifer)
        {
			if(String.IsNullOrWhiteSpace(identifer))
			   return null;
            return new KeyType(identifer);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyType"/> class.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        public KeyType(string identifer)
            : base(identifer)
        {


        }

		public static KeyType Name(string identifier){
			return identifier;
		}

        private Type _type;
        private int[] _keySizeOptions;
        private bool? _unofficial;
        private bool? _asymmetric;
        /// <summary>
        /// Gets the key size options.
        /// </summary>
        /// <value>The key size options.</value>
        public int[] KeySizeOptions
        {
            get
            {
                if (_keySizeOptions == null)
                {
                    _keySizeOptions = _specs[Identifier].KeySizes;
                }
                return _keySizeOptions;
            }
        }

        /// <summary>
        /// Gets the clr type.
        /// </summary>
        /// <value>The type.</value>
        public virtual Type Type
        {
            get
            {
                if (_type == null)
                {
                    _type = _specs[Identifier].Type;
                }
                return _type;
			}set{}
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="KeyType"/> is a public key.
        /// </summary>
        /// <value><c>true</c> if public; otherwise, <c>false</c>.</value>
        public bool Asymmetric
        {
            get
            {
                if (!_asymmetric.HasValue)
                {
                    _asymmetric = _specs[Identifier].Asymmetric;
                }
                return _asymmetric.Value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="KeyType"/> is unofficial.
        /// </summary>
        /// <value><c>true</c> if unofficial; otherwise, <c>false</c>.</value>
        public bool Unofficial
        {
           get
           {
               if (!_unofficial.HasValue)
               {
                   _unofficial = _specs[Identifier].Unofficial;
               }
               return _unofficial.Value;
           }
        }

        /// <summary>
        /// Gets the default size.
        /// </summary>
        /// <value>The default size.</value>
        public int DefaultSize
        {
            get { return KeySizeOptions.FirstOrDefault(); }
        }
    }
}