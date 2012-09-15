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
using System.Text;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Crypto;
using Keyczar.Unofficial;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture,Category("Create")]
    public class CreateManageTest:AssertionHelper
    {    
        private static string WRITE_DATA = "cstestdata";
        private static String input = "This is some test data";

        private MutableKeySet CreateNewKeySet(KeyType type, KeyPurpose purpose)
        {
            return new MutableKeySet(new KeyMetadata
                {
                    Name = "Test",
                    Purpose = purpose,
                    Type = type
                });
        }

        [TestCase("aes","aes","")]
        [TestCase("c#_aes_aead", "aes_aead", "unofficial", Category = "Unofficial")]
        public void CreateAndCrypted(string keyType, string topDir, string subDir)
        {
            KeyType type = keyType;
            var kspath = Util.TestDataPath(WRITE_DATA, topDir, subDir);
            var writer =new KeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(type, KeyPurpose.DECRYPT_AND_ENCRYPT))
            {
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            HelperCryptCreate(writer, new KeySet(kspath),  kspath);

            var kscryptpath = Util.TestDataPath(WRITE_DATA, topDir+"-crypted", subDir);


            var baseWriter = new KeySetWriter(kscryptpath, overwrite: true);
            using (var ks = CreateNewKeySet(type, KeyPurpose.DECRYPT_AND_ENCRYPT))
            {
                var success = ks.Save(baseWriter);
                Expect(success, Is.True);
            }

            using(var encrypter = new Crypter(kspath))
            {
                var cryptedwriter = new EncryptedKeySetWriter(baseWriter, encrypter);
                HelperCryptCreate(cryptedwriter, new EncryptedKeySet(kscryptpath,encrypter), kscryptpath);
            }

        }
        

		[Test]
		public void CreatePbeKeySet(){

			var kspath = Util.TestDataPath(WRITE_DATA, "pbe_json");
			var writer =new KeySetWriter(kspath, overwrite: true);
			Func<string> passPrompt = ()=>"cartman"; //hardcoded because this is a test;
			var encwriter =new PbeKeySetWriter(writer,passPrompt);

			using (var ks = CreateNewKeySet(KeyType.AES, KeyPurpose.DECRYPT_AND_ENCRYPT))
			{
				var success = ks.Save(writer);
				Expect(success, Is.True);
			}
			using(var eks = new PbeKeySet(kspath,passPrompt)){
				HelperCryptCreate(encwriter,eks,  kspath);
			}


		}

		[TestCase("aes","aes-noprimary")]
		public void CreateNoPrimary(string keyType, string topDir)
		{
			KeyType type = keyType;
			var kspath = Util.TestDataPath(WRITE_DATA, topDir);
			var writer =new KeySetWriter(kspath, overwrite: true);
			
			using (var ks = CreateNewKeySet(type, KeyPurpose.DECRYPT_AND_ENCRYPT))
			{
				int ver = ks.AddKey(KeyStatus.PRIMARY);
				Expect(ver, Is.EqualTo(1));

				var success = ks.Save(writer);
				Expect(success, Is.True);
			}

			using (var encrypter = new Encrypter(kspath))
			{
				var ciphertext = encrypter.Encrypt(input);
				File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
			}

			using (var ks = new MutableKeySet(kspath))
			{
				var status = ks.Demote(1);
				Expect(status, Is.EqualTo(KeyStatus.ACTIVE));

				var success = ks.Save(writer);
				Expect(success, Is.True);
			} 

		}

        [TestCase("hmac_sha1", "hmac")]
        [TestCase("dsa_priv", "dsa")]
        [TestCase("rsa_priv", "rsa-sign")]
        public void CreateSignAndPublic(string keyType, string topDir)
        {
            KeyType type = keyType;
            var kspath = Util.TestDataPath(WRITE_DATA, topDir);
            var writer = new KeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(type, KeyPurpose.SIGN_AND_VERIFY))
            {
                var ver = ks.AddKey(KeyStatus.PRIMARY);
				Expect(ver, Is.EqualTo(1));
			
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            using (var encrypter = new Signer(kspath))
            {
                var ciphertext = encrypter.Sign(input);
                File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
            }

            using (var ks = new MutableKeySet(kspath))
            {
                var ver = ks.AddKey(KeyStatus.PRIMARY);
				Expect(ver, Is.EqualTo(2));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            } 
            
            using (var encrypter = new Signer(kspath))
            {
                var ciphertext = encrypter.Sign(input);
                File.WriteAllText(Path.Combine(kspath, "2.out"), ciphertext);
            }

            if (type.Asymmetric)
            {
                var kspath2 = Util.TestDataPath(WRITE_DATA, topDir + ".public");
                var writer2 = new KeySetWriter(kspath2, overwrite: true);
                using (var ks = new MutableKeySet(kspath))
                {


                    var pubKs = ks.PublicKey();
                    var success = pubKs.Save(writer2);
                    Expect(success, Is.True);
                }
            }

        }



        [TestCase("rsa_priv", "rsa")]
        public void CreateEncryptAndPublic(string keyType, string topDir)
        {
            KeyType type = keyType;
            var kspath = Util.TestDataPath(WRITE_DATA, topDir);
            var writer = new KeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(type, KeyPurpose.DECRYPT_AND_ENCRYPT))
            {
                var ver = ks.AddKey(KeyStatus.PRIMARY);
                Expect(ver, Is.EqualTo(1));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            using (var encrypter = new Encrypter(kspath))
            {
                var ciphertext = encrypter.Encrypt(input);
                File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
            }

            using (var ks = new MutableKeySet(kspath))
            {
                var ver = ks.AddKey(KeyStatus.PRIMARY);
                Expect(ver, Is.EqualTo(2));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            using (var encrypter = new Encrypter(kspath))
            {
                var ciphertext = encrypter.Encrypt(input);
                File.WriteAllText(Path.Combine(kspath, "2.out"), ciphertext);
            }

            if (type.Asymmetric)
            {
                var kspath2 = Util.TestDataPath(WRITE_DATA, topDir + ".public");
                var writer2 = new KeySetWriter(kspath2, overwrite: true);
                using (var ks = new MutableKeySet(kspath))
                {


                    var pubKs = ks.PublicKey();
                    var success = pubKs.Save(writer2);
                    Expect(success, Is.True);
                }
            }

        }


        [TestCase("dsa_priv","SIGN_AND_VERIFY", "dsa-sign")]
        [TestCase("rsa_priv", "SIGN_AND_VERIFY", "rsa-sign")]
        [TestCase("rsa_priv", "DECRYPT_AND_ENCRYPT", "rsa-crypt")]
        public void TestExportPem(string keyType,string purpose, string topDir)
        {
            KeyPurpose p = purpose;
            KeyType kt = keyType;

            var path = Util.TestDataPath(WRITE_DATA, topDir, "certificates");
            var pubPath = path + "-pub";
            var exportPath = path + "-pkcs8.pem";


            var writer = new KeySetWriter(path, overwrite: true);
            var pubWriter = new KeySetWriter(pubPath, overwrite: true);
            using (var ks = CreateNewKeySet(kt, p))
            {
                var ver =ks.AddKey(KeyStatus.PRIMARY);
                Expect(ver, Is.EqualTo(1));

                using (var pubks = ks.PublicKey())
                {
                    var pubsuccess = pubks.Save(pubWriter);
                    Expect(pubsuccess, Is.True);
                }
                Func<string> password = () => "pass";//Hardcoding because this is a test

                var success = ks.ExportPrimaryAsPKCS(exportPath, password);
                Expect(success, Is.True);

                success = ks.Save(writer);
                Expect(success, Is.True);
            }
        }

        [Test]
        [Category("Create")]
        [Category("Unofficial")]
        public void TestCreateBlob()
        {
            Directory.CreateDirectory(WRITE_DATA);

            var keyMetaData = new KeyMetadata
            {
                Name = "Blob",
                Purpose = KeyPurpose.DECRYPT_AND_ENCRYPT,
                Type = KeyType.AES
            };
            using (var keySet = new MutableKeySet(keyMetaData))
            {
                keySet.AddKey(KeyStatus.PRIMARY, 256);

                using (var stream = File.OpenWrite(Util.TestDataPath(WRITE_DATA, "cryptkey.zip","unofficial")))
                using (var writer = new BlobKeySetWriter(stream))
                {
                    keySet.Save(writer);
                }

                using (var crypt = new Crypter(keySet))
                {
                    File.WriteAllText(Util.TestDataPath(WRITE_DATA, "crypt.out", "unofficial"), crypt.Encrypt(input));
                    var keyMetaData2 = new KeyMetadata
                    {
                        Name = "Blob",
                        Purpose = KeyPurpose.SIGN_AND_VERIFY,
                        Type = KeyType.RSA_PRIV
                    };
                    using (var keySet2 = new MutableKeySet(keyMetaData2))
                    {
                        keySet2.AddKey(KeyStatus.PRIMARY);
                        using (var stream2 = File.OpenWrite(Util.TestDataPath(WRITE_DATA, "signkey.zip", "unofficial")))
                        using (var writer2 = new BlobKeySetWriter(stream2))
                        {
                            keySet2.Save(new EncryptedKeySetWriter(writer2, crypt));
                        }

                        using (var signer = new Signer(keySet2))
                        {
                            File.WriteAllText(Path.Combine(WRITE_DATA, "sign.out"), signer.Sign(input));
                        }
                    }
                }


            }


        }


        private void HelperCryptCreate(IKeySetWriter writer, IKeySet keySet, string kspath)
        {
            using (var ks = new MutableKeySet(keySet))
            {
                var ver = ks.AddKey(KeyStatus.PRIMARY);
				Expect(ver, Is.EqualTo(1));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            using (var encrypter = new Encrypter(keySet))
            {
                var ciphertext = encrypter.Encrypt(input);
                File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
            }

            using (var ks = new MutableKeySet(keySet))
            {
				var ver = ks.AddKey(KeyStatus.PRIMARY);
				Expect(ver, Is.EqualTo(2));
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            using (var encrypter = new Encrypter(keySet))
            {
                var ciphertext = encrypter.Encrypt(input);
                File.WriteAllText(Path.Combine(kspath, "2.out"), ciphertext);
            }
        }
    }
}
