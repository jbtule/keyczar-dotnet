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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Keyczar.Compat;


using Keyczar.Crypto;
using Keyczar.Crypto.Streams;
using Keyczar.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Security;

namespace Keyczar.Pbe
{
    /// <summary>
    /// Stores a key encrypted by password
    /// </summary>
    public class PbeKeyStore
    {

        /// <summary>
        /// Random number generator
        /// </summary>
        protected static readonly SecureRandom Random = new SecureRandom();

        /// <summary>
        /// Encrypts the key data.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="passswordPrompt">The passsword prompt.</param>
        /// <param name="interationCount">The interation count.</param>
        /// <returns></returns>
        public static PbeKeyStore EncryptKeyData(byte[] key, Func<string> passswordPrompt, int interationCount)
        {


            var pks = new PbeKeyStore()
                          {
                              Cipher = PbeKeyType.AES_128,
                              Hmac = PbeHashType.HMAC_SHA1,
                              IterationCount = interationCount,
                              Salt = new byte[16]
                          };

            Random.NextBytes(pks.Salt);

            var pbeKey = new PbeAesKey(){Size = 128};
            pbeKey.AesKeyBytes = pks.GetDerivedBytes(pbeKey.Size / 8, passswordPrompt);
            pks.IV = pbeKey.IV;

            using (pbeKey)
            using (var ks = new ImportedKeySet(pbeKey, KeyPurpose.DECRYPT_AND_ENCRYPT, "Pbe key"))
            using (var crypter = new Crypter(ks))
            {
                pks.Key = crypter.Encrypt(key);
            }

            return pks;
        }


        /// <summary>
        /// Gets or sets the cipher.
        /// </summary>
        /// <value>The cipher.</value>
        public PbeKeyType Cipher { get; set; }

        /// <summary>
        /// Gets or sets the hmac.
        /// </summary>
        /// <value>The hmac.</value>
        public PbeHashType Hmac { get; set; }

        /// <summary>
        /// Gets or sets the iteration count.
        /// </summary>
        /// <value>The iteration count.</value>
        public int IterationCount { get; set; }

        /// <summary>
        /// Gets or sets the IV.
        /// </summary>
        /// <value>The IV.</value>
        [JsonConverter(typeof(WebSafeBase64ByteConverter))]
        public byte[] IV { get; set; }

        /// <summary>
        /// Gets or sets the encrypted key.
        /// </summary>
        /// <value>The key.</value>
        [JsonConverter(typeof(WebSafeBase64ByteConverter))]
        public byte[] Key { get; set; }

        /// <summary>
        /// Gets or sets the salt.
        /// </summary>
        /// <value>The salt.</value>
        [JsonConverter(typeof(WebSafeBase64ByteConverter))]
        public byte[] Salt { get; set; }


        /// <summary>
        /// Gets the derived bytes using the store's parameters
        /// </summary>
        /// <param name="length">The length.</param>
        /// <param name="passswordPrompt">The passsword prompt.</param>
        /// <returns></returns>
        protected byte[] GetDerivedBytes(int length, Func<string> passswordPrompt)
        {
            Rfc2898DeriveBytes pdb;
            if (Hmac == PbeHashType.HMAC_SHA1)
            {
                pdb = new Rfc2898DeriveBytes(passswordPrompt(), Salt, IterationCount);
            }
            else if (Hmac == PbeHashType.HMAC_SHA256)
            {
                throw new InvalidKeySetException("Hmac_Sha256 not supported.");
            }
            else
            {
                throw new InvalidKeySetException("Unknown Pbe Cipher");
            }
            using (pdb)
            {
                return pdb.GetBytes(length);
            }
        }

        /// <summary>
        /// Decrypts the key data.
        /// </summary>
        /// <param name="passswordPrompt">The passsword prompt.</param>
        /// <returns></returns>
        public byte[] DecryptKeyData(Func<string> passswordPrompt)
        {
            var key = new PbeAesKey { IV = IV };

            if (Cipher == PbeKeyType.AES_128)
            {
                key.Size = 128;
            }
            else
            {
                throw new InvalidKeySetException("Unknown Pbe Cipher");
            }

            key.AesKeyBytes = GetDerivedBytes(key.Size/8, passswordPrompt);

                using (key)
                using(var ks = new ImportedKeySet(key,KeyPurpose.DECRYPT_AND_ENCRYPT,"Pbe key"))
                using(var crypter = new Crypter(ks))
                {
                     return crypter.Decrypt(Key);
                }
            

        }

		[JsonConverter(typeof(JsonConverter))]
		internal class HardcodedKeyType:KeyType{
			Type _type;
			internal HardcodedKeyType(String identifer,Type type):base(identifer){
				_type =type;
			}

			public override Type Type{
				get{
					return _type;
				}set{
					_type = value;
				}
			}
		}


        internal class PbeAesKey : AesKey, IPbeKey
        {

            internal PbeAesKey()
            {
                IV = new byte[16];
                Random.NextBytes(IV);
            }

			KeyType _type =new HardcodedKeyType("PBE_AES",typeof(PbeAesKey));

			[JsonProperty(TypeNameHandling = TypeNameHandling.Objects)]
			public override KeyType Type {
				get {
					return _type;
				}set{
					_type =value;
				}
			}

			public override byte[] GetKeyHash()
			{
				return Utility.GetBytes(0);
			}

            public byte[] IV { get; set; }

            public CipherTextOnlyFinishingStream GetRawEncryptingStream(Stream output)
            {
                var stream = (CipherTextOnlyFinishingStream)GetEncryptingStream(output);
                stream.CipherTextOnly = true;
                stream.IV = IV;
                return stream;
            }

            public CipherTextOnlyFinishingStream GetRawDecryptingStream(Stream output)
            {
                var stream = (CipherTextOnlyFinishingStream)GetDecryptingStream(output);
                stream.CipherTextOnly = true;
                stream.IV = IV;
                return stream;
            }

        }
    }

    /// <summary>
    /// Type of cipher to use for encrypting keys with password.
    /// </summary>
    public class PbeKeyType : StringType
    {
        /// <summary>
        /// AES 128
        /// </summary>
        public static readonly PbeKeyType AES_128 = "AES128";


        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="PbeKeyType"/>.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator PbeKeyType(string identifer)
        {
            return new PbeKeyType(identifer);
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="PbeKeyType"/> class.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        public PbeKeyType(string identifer) : base(identifer)
        {
        }
    }

    /// <summary>
    /// Type of Hash to use for the Password Derived Bytes
    /// </summary>
    public class PbeHashType : StringType
    {
        /// <summary>
        /// Hmac Sha1
        /// </summary>
        public static readonly PbeHashType HMAC_SHA1 = "HMAC_SHA1";
        /// <summary>
        /// Hmac Sha256
        /// </summary>
        public static readonly PbeHashType HMAC_SHA256 = "HMAC_SHA256";

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="PbeHashType"/>.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator PbeHashType(string identifer)
        {
            return new PbeHashType(identifer);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PbeHashType"/> class.
        /// </summary>
        /// <param name="identifer">The identifer.</param>
        public PbeHashType(string identifer) : base(identifer)
        {
        }
    }
}
