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
using System.ComponentModel;
using System.Linq;
using Keyczar.Crypto;
using Keyczar.Unofficial;

namespace Keyczar
{
    /// <summary>
    /// Metadata for Key Types
    /// </summary> 
    [ImmutableObject(true)]
    public class KeyType : Util.StringType
    {
        /// <summary>
        /// Aes key
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType Aes = "AES";

        /// <summary>
        /// Hmac Sha1 key
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType HmacSha1 = "HMAC_SHA1";

        /// <summary>
        /// DSA Private Key
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType DsaPriv = "DSA_PRIV";

        /// <summary>
        /// Dsa Public key
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType DsaPub = "DSA_PUB";

        /// <summary>
        /// RSA private key
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType RsaPriv = "RSA_PRIV";

        /// <summary>
        /// Rsa public key type
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security",
            "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")] public static readonly KeyType RsaPub = "RSA_PUB";


        /// <summary>
        /// Get KeyType for the clr type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        public static KeyType ForType(Type type)
        {
            return _specs.Where(it => it.Value.RepresentedType == type).Select(it => it.Key).FirstOrDefault();
        }
        
        

        /// <summary>
        /// Defines the spec.
        /// </summary>
        /// <param name="spec">The spec.</param>
        /// <returns></returns>

        protected static bool DefineSpec(KeyTypeSpec spec)
        {
            if (_specs.ContainsKey(spec.Name.Identifier))
            {
                return false;
            }
            if (_specs.Select(it => it.Value.RepresentedType).Any(it => it == spec.RepresentedType))
            {
                throw new InvalidKeyTypeException($"KeyType's spec already exists for {spec.RepresentedType}");
            }
            _specs.Add(spec.Name.Identifier, spec);
            return true;
        }

        static KeyType()
        {
            Aes.KeySizes<AesKey>(128, 192, 256).DefineSpec();
            HmacSha1.KeySizes<HmacSha1Key>(256).DefineSpec();
            DsaPriv.KeySizes<DsaPrivateKey>().WeakSizes(1024).IsAsymmetric().DefineSpec();
            DsaPub.KeySizes<DsaPublicKey>().WeakSizes(1024).IsAsymmetric().IsPublic().DefineSpec();
            RsaPriv.KeySizes<RsaPrivateKey>(2048, 4096).WeakSizes(1024).IsAsymmetric().DefineSpec();
            RsaPub.KeySizes<RsaPublicKey>(2048, 4096).WeakSizes(1024).IsAsymmetric().IsPublic().DefineSpec();

            var dummy = UnofficialKeyType.AesAead;// inference first run construction - lgtm [cs/useless-assignment-to-local]
            dummy = UnofficialKeyType.RSAPrivSign;// inference first run construction - lgtm [cs/useless-assignment-to-local]
            dummy = UnofficialKeyType.RSAPubSign; // inference first run construction - lgtm [cs/useless-assignment-to-local]

        }

        private static readonly IDictionary<string, KeyTypeSpec> _specs = new Dictionary<string, KeyTypeSpec>();


        public static IEnumerable<KeyTypeSpec> Specs => _specs.Values;

        /// <summary>
        /// Describes the sizes and algorithms.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="keySizes">The key sizes.</param>
        /// <returns></returns>
        public KeyTypeSpec KeySizes<T>(params int[] keySizes) where T : Key
        {
            return new KeyTypeSpec
                       {
                           Name = Identifier,
                           RepresentedType = typeof (T),
                           GoodKeySizes = keySizes,
                           WeakKeySizes = Enumerable.Empty<int>(),
                       };
        }

        /// <summary>
        /// Describes meta data about keytypes
        /// </summary>
        public class KeyTypeSpec
        {
            internal KeyTypeSpec()
            {
            }


            /// <summary>
            /// Gets or sets the name.
            /// </summary>
            /// <value>The name.</value>
            public KeyType Name { get; internal set; }

            /// <summary>
            /// Gets or sets the type.
            /// </summary>
            /// <value>The type.</value>
            public Type RepresentedType { get; internal set; }

            /// <summary>
            /// Gets or sets the key sizes.
            /// </summary>
            /// <value>The key sizes.</value>
            [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance",
                "CA1819:PropertiesShouldNotReturnArrays")]
            public IEnumerable<int> KeySizes => GoodKeySizes.Concat(WeakKeySizes);
            
            public IEnumerable<int> GoodKeySizes { get; internal set; }

            public IEnumerable<int> WeakKeySizes { get; internal set; }

            
            /// <summary>
            /// Gets or sets a value indicating whether this <see cref="KeyTypeSpec"/> is unofficial.
            /// </summary>
            /// <value><c>true</c> if unofficial; otherwise, <c>false</c>.</value>
            public bool Unofficial { get; internal set; }

            /// <summary>
            /// Gets or sets a value indicating whether this <see cref="KeyTypeSpec"/> is asymmetric.
            /// </summary>
            /// <value><c>true</c> if asymmetric; otherwise, <c>false</c>.</value>
            public bool Asymmetric { get; internal set; }

            /// <summary>
            /// Gets or sets a value indicating whether this <see cref="KeyTypeSpec"/> is asymmetric.
            /// </summary>
            /// <value><c>true</c> if asymmetric; otherwise, <c>false</c>.</value>
            public bool Public { get; internal set; }
            
            /// <summary>
            /// Gets or sets a value indicating whether this <see cref="KeyTypeSpec"/> is not for actual use.
            /// </summary>
            /// <value><c>true</c> if temp; otherwise, <c>false</c>.</value>
            public bool Temp { get; internal set; }

            /// <summary>
            /// Specifies this  instance is unofficial.
            /// </summary>
            /// <returns></returns>
            public KeyTypeSpec IsUnofficial()
            {
                Unofficial = true;
                return this;
            }

            /// <summary>
            /// Specifies this instance is asymmetric.
            /// </summary>
            /// <returns></returns>
            public KeyTypeSpec IsAsymmetric()
            {
                Asymmetric = true;
                return this;
            }


            /// <summary>
            /// Specifies this instance is public.
            /// </summary>
            /// <returns></returns>
            public KeyTypeSpec IsPublic()
            {
                Public = true;
                return this;
            }

            public KeyTypeSpec WeakSizes(params int[] keySizes)
            {
                WeakKeySizes = WeakKeySizes.Concat(keySizes);
                return this;
            }
            
            /// <summary>
            /// Specifies this instance is temp key type.
            /// </summary>
            /// <returns></returns>
            public KeyTypeSpec IsTemp()
            {
                Temp = true;
                return this;
            }

            /// <summary>
            /// Defines the spec.
            /// </summary>
            /// <returns></returns>
            public KeyType DefineSpec()
            {
                if (KeyType.DefineSpec(this))
                    return Name;
                return null;
            }
        }

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="KeyType"/>.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The result of the conversion.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Constructor is alternative")]
        public static implicit operator KeyType(string identifier)
        {
            if (String.IsNullOrWhiteSpace(identifier))
                return null;
            return new KeyType(identifier);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyType"/> class.
        /// </summary>
        /// <param name="identifier">The identifer.</param>
        public KeyType(string identifier)
            : base(identifier)
        {
        }

        /// <summary>
        /// Returns or creates a keytype
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns></returns>
        public static KeyType Name(string identifier)
        {
            return identifier;
        }

        private Type _representedType;
        private int[] _keySizeOptions;
        private bool? _unofficial;
        private bool? _asymmetric;
        private bool? _public;


        /// <summary>
        /// Gets the key size options.
        /// </summary>
        /// <value>The key size options.</value>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance",
            "CA1819:PropertiesShouldNotReturnArrays")]
        public int[] KeySizeOptions
        {
            get
            {
                if (_keySizeOptions == null)
                {
                    _keySizeOptions = _specs[Identifier].KeySizes.ToArray();
                }
                return _keySizeOptions;
            }
        }

        /// <summary>
        /// Gets the clr type.
        /// </summary>
        /// <value>The type.</value>
        public virtual Type RepresentedType
        {
            get
            {
                if (_representedType == null)
                {
                    _representedType = _specs[Identifier].RepresentedType;
                }
                return _representedType;
            }
            set { }
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="KeyType"/> is an Asymmetric key.
        /// </summary>
        /// <value><c>true</c> if Asymmetric; otherwise, <c>false</c>.</value>
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
        /// Gets a value indicating whether this <see cref="KeyType"/> is a public key.
        /// </summary>
        /// <value><c>true</c> if public; otherwise, <c>false</c>.</value>
        public bool Public
        {
            get
            {
                if (!_public.HasValue)
                {
                    _public = _specs[Identifier].Public;
                }
                return _public.Value;
            }
        }

        /// <summary>
        /// Gets the kind of the key.
        /// </summary>
        /// <value>
        /// The kind of the key.
        /// </value>
        public virtual KeyKind Kind
        {
            get
            {
                if (Asymmetric)
                {
                    if (Public)
                    {
                        return KeyKind.Public;
                    }
                    return KeyKind.Private;
                }
                return KeyKind.Symmetric;
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
        public int DefaultSize => KeySizeOptions.FirstOrDefault();
    }
}