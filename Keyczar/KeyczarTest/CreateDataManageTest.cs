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
using System.Text;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Unofficial;
using Keyczar.Util;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture, Category("Create")]
    public class CreateDataManageTest : AssertionHelper
    {
        private static string WRITE_DATA = Path.Combine("gen-testdata", "cstestdata");
        private static String input = "This is some test data";


        private MutableKeySet CreateNewKeySet(KeyKind type, KeyPurpose purpose, string name = null)
        {
            return new MutableKeySet(new KeyMetadata
                                         {
                                             Name = name ?? "Test",
                                             Purpose = purpose,
                                             Kind = type
                                         });
        }

        [TestCase("aes", "aes", "")]
        [TestCase("c#_aes_aead", "aes_aead", "unofficial", Category = "Unofficial")]
        public void CreateAndCrypted(string keyType, string topDir, string subDir)
        {
            KeyType type = keyType;
            var kspath = Util.TestDataPath(WRITE_DATA, topDir, subDir);
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(type.Kind, KeyPurpose.DecryptAndEncrypt))
            {
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }


            HelperCryptCreate(writer, new FileSystemKeySet(kspath), kspath, type);


            var kscryptpath = Util.TestDataPath(WRITE_DATA, topDir + "-crypted", subDir);


            var baseWriter = new FileSystemKeySetWriter(kscryptpath, overwrite: true);
            using (var ks = CreateNewKeySet(type.Kind, KeyPurpose.DecryptAndEncrypt))
            {
                var success = ks.Save(baseWriter);
                Expect(success, Is.True);
            }

            using (var encrypter = new Crypter(kspath))
            {
                var cryptedwriter = new EncryptedKeySetWriter(baseWriter, encrypter);
                using (var eks = KeySet.LayerSecurity(FileSystemKeySet.Creator(kscryptpath),
                                                      EncryptedKeySet.Creator(encrypter)))
                {
                    HelperCryptCreate(cryptedwriter, eks, kscryptpath, type,
                                      new FileSystemKeySet(kscryptpath), baseWriter);
                }
            }
        }


        [TestCase("aes", "aes", "128", "crypt")]
        [TestCase("hmac_sha1", "hmac", "256", "sign")]
        //Asymentric key genteration is too slow
        //[TestCase("rsa_priv", "rsa", "1024", "crypt")]
        //[TestCase("rsa_priv", "rsa-sign", "1024", "sign")]
        //[TestCase("dsa_priv", "dsa", "1024", "sign")]
        public void CreateKeyCollision(string key, string dir, string sizeString, string purpose)
        {
            var crypt = purpose == "crypt";
            var purp = crypt ? KeyPurpose.DecryptAndEncrypt : KeyPurpose.SignAndVerify;
            KeyType ktype = key;
            int size = int.Parse(sizeString);

            IDictionary<int, Key> keys = new Dictionary<int, Key>();
            var kspath = Util.TestDataPath(WRITE_DATA, dir, "key-collision");
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(ktype.Kind, purp))
            {
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }


            long count = 0;
            Key newKey2;
            using (var ks = new MutableKeySet(kspath))
            {
                Key newKey1;
                while (true)
                {
                    newKey1 = Key.Generate(ktype, size);
                    int newHash = Utility.ToInt32(newKey1.GetKeyHash());
                    count++;
                    if (keys.TryGetValue(newHash, out newKey2))
                    {
                        break;
                    }
                    keys.Add(newHash, newKey1);
                }
                Console.WriteLine("Created {1} collision after {0} iterations", count, dir);

                var ver = ks.AddKey(KeyStatus.Primary, newKey1);

                Expect(ver, Is.EqualTo(1));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            if (crypt)
            {
                using (var encrypter = new Encrypter(kspath))
                {
                    var ciphertext = encrypter.Encrypt(input);
                    File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
                }
            }
            else
            {
                using (var signer = new Signer(kspath))
                {
                    var ciphertext = signer.Sign(input);
                    File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
                }

                using (var signer = new TimeoutSigner(kspath))
                {
                    var ciphertext = signer.Sign(input, new DateTime(2012, 12, 21, 11, 11, 0, DateTimeKind.Utc));
                    File.WriteAllText(Path.Combine(kspath, "1.timeout"), ciphertext);
                }

                using (var signer = new AttachedSigner(kspath))
                {
                    var ciphertext = signer.Sign(input);
                    File.WriteAllText(Path.Combine(kspath, "1.attached"), ciphertext);
                }

                using (var signer = new AttachedSigner(kspath))
                {
                    var ciphertext = signer.Sign(input, Encoding.UTF8.GetBytes("secret"));
                    File.WriteAllText(Path.Combine(kspath, "1.secret.attached"), ciphertext);
                }
            }

            using (var ks = new MutableKeySet(kspath))
            {
                var ver = ks.AddKey(KeyStatus.Primary, newKey2);
                Expect(ver, Is.EqualTo(2));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }
            if (crypt)
            {
                using (var encrypter = new Encrypter(kspath))
                {
                    var ciphertext = encrypter.Encrypt(input);
                    File.WriteAllText(Path.Combine(kspath, "2.out"), ciphertext);
                }
            }
            else
            {
                using (var signer = new Signer(kspath))
                {
                    var ciphertext = signer.Sign(input);
                    File.WriteAllText(Path.Combine(kspath, "2.out"), ciphertext);
                }


                using (var signer = new TimeoutSigner(kspath))
                {
                    var ciphertext = signer.Sign(input, new DateTime(2012, 12, 21, 11, 11, 0, DateTimeKind.Utc));
                    File.WriteAllText(Path.Combine(kspath, "2.timeout"), ciphertext);
                }

                using (var signer = new AttachedSigner(kspath))
                {
                    var ciphertext = signer.Sign(input);
                    File.WriteAllText(Path.Combine(kspath, "2.atttached"), ciphertext);
                }

                using (var signer = new AttachedSigner(kspath))
                {
                    var ciphertext = signer.Sign(input, Encoding.UTF8.GetBytes("secret"));
                    File.WriteAllText(Path.Combine(kspath, "2.secret.atttached"), ciphertext);
                }
            }
        }

        [Test]
        public void CreatePbeKeySet()
        {
            var kspath = Util.TestDataPath(WRITE_DATA, "pbe_json");
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);
            Func<string> passPrompt = () => "cartman"; //hardcoded because this is a test;
            using (var encwriter = new PbeKeySetWriter(writer, passPrompt))
            {
                using (var ks = CreateNewKeySet(KeyKind.Symmetric, KeyPurpose.DecryptAndEncrypt))
                {
                    var success = ks.Save(writer);
                    Expect(success, Is.True);
                }
                using (var eks = KeySet.LayerSecurity(
                    FileSystemKeySet.Creator(kspath),
                    PbeKeySet.Creator(passPrompt)))
                {
                    HelperCryptCreate(encwriter, eks, kspath, KeyType.Aes);
                }
            }
        }

        [TestCase("aes", "aes-noprimary")]
        public void CreateNoPrimary(string keyType, string topDir)
        {
            KeyType type = keyType;
            var kspath = Util.TestDataPath(WRITE_DATA, topDir);
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);


            using (var ks = CreateNewKeySet(type.Kind, KeyPurpose.DecryptAndEncrypt))
            {
                int ver = ks.AddKey(KeyStatus.Primary, type:type);
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
                Expect(status, Is.EqualTo(KeyStatus.Active));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }
        }

        [TestCase("hmac_sha1", "hmac", "")]
        [TestCase("dsa_priv", "dsa", "")]
        [TestCase("rsa_priv", "rsa-sign", "")]
        [TestCase("c#_rsa_sign_priv", "rsa-sign", "unofficial", Category = "Unofficial")]
        public void CreateSignAndPublic(string keyType, string topDir, string nestDir)
        {
            KeyType type = keyType;
            var kspath = Util.TestDataPath(WRITE_DATA, topDir, nestDir);
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(type.Kind, KeyPurpose.SignAndVerify))
            {
                var ver = ks.AddKey(KeyStatus.Primary, type: type);
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
                var ver = ks.AddKey(KeyStatus.Primary, type: type);
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
                var kspath2 = Util.TestDataPath(WRITE_DATA, topDir + ".public", nestDir);
                var writer2 = new FileSystemKeySetWriter(kspath2, overwrite: true);
                using (var ks = new MutableKeySet(kspath))
                {
                    var pubKs = ks.PublicKey();
                    var success = pubKs.Save(writer2);
                    Expect(success, Is.True);
                }
            }
        }


        [TestCase("hmac_sha1", "hmac", "")]
        [TestCase("dsa_priv", "dsa", "")]
        [TestCase("rsa_priv", "rsa-sign", "")]
        [TestCase("c#_rsa_sign_priv", "rsa-sign", "unofficial", Category = "Unofficial")]
        public void CreateSignAndPublicSized(string keyType, string topDir, string nestDir)
        {
            KeyType type = keyType;
            topDir += "-sizes";
            var kspath = Util.TestDataPath(WRITE_DATA, topDir, nestDir);
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);


            using (var ks = CreateNewKeySet(type.Kind, KeyPurpose.SignAndVerify))
            {
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            int i = 0;
            foreach (int size in type.KeySizeOptions)
            {
                i++;
                using (var ks = new MutableKeySet(kspath))
                {
                    var ver = ks.AddKey(KeyStatus.Primary, size, type:type);
                    Expect(ver, Is.EqualTo(i));

                    var success = ks.Save(writer);
                    Expect(success, Is.True);
                }

                using (var encrypter = new Signer(kspath))
                {
                    var ciphertext = encrypter.Sign(input);
                    File.WriteAllText(Path.Combine(kspath, String.Format("{0}.out", size)), ciphertext);
                }
            }

            if (type.Asymmetric)
            {
                var kspath2 = Util.TestDataPath(WRITE_DATA, topDir + ".public", nestDir);
                var writer2 = new FileSystemKeySetWriter(kspath2, overwrite: true);
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
            var writer = new FileSystemKeySetWriter(kspath, overwrite: true);

            using (var ks = CreateNewKeySet(type.Kind, KeyPurpose.DecryptAndEncrypt))
            {
                var ver = ks.AddKey(KeyStatus.Primary, type:type);
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
                var ver = ks.AddKey(KeyStatus.Primary, type: type);
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
                var writer2 = new FileSystemKeySetWriter(kspath2, overwrite: true);
                using (var ks = new MutableKeySet(kspath))
                {
                    var pubKs = ks.PublicKey();
                    var success = pubKs.Save(writer2);
                    Expect(success, Is.True);
                }
            }
        }


        [TestCase("dsa_priv", "SIGN_AND_VERIFY", "dsa-sign")]
        [TestCase("rsa_priv", "SIGN_AND_VERIFY", "rsa-sign")]
        [TestCase("rsa_priv", "DECRYPT_AND_ENCRYPT", "rsa-crypt")]
        [TestCase("c#_rsa_sign_priv", "SIGN_AND_VERIFY", "rsa-sign-unofficial", Category = "Unofficial")]
        public void TestExportPem(string keyType, string purpose, string topDir)
        {
            KeyPurpose p = purpose;
            KeyType kt = keyType;

            var path = Util.TestDataPath(WRITE_DATA, topDir, "certificates");
            var pubPath = path + ".public";
            var exportPath = path + "-pkcs8.pem";
            var exportPubPath = path + "-public.pem";

            var writer = new FileSystemKeySetWriter(path, overwrite: true);
            var pubWriter = new FileSystemKeySetWriter(pubPath, overwrite: true);
            using (var ks = CreateNewKeySet(kt.Kind, p))
            {
                var ver = ks.AddKey(KeyStatus.Primary, type: kt);
                Expect(ver, Is.EqualTo(1));

                using (var pubks = ks.PublicKey())
                {
                    var pubsuccess = pubks.Save(pubWriter);
                    Expect(pubsuccess, Is.True);

                    pubsuccess = pubks.ExportPrimaryAsPkcs(exportPubPath, () => null);
                    Expect(pubsuccess, Is.True);
                }
                Func<string> password = () => "pass"; //Hardcoding because this is a test

                var success = ks.ExportPrimaryAsPkcs(exportPath, password);
                Expect(success, Is.True);

                success = ks.Save(writer);
                Expect(success, Is.True);
            }
        }


        [TestCase("rsa", "", "", "", "session.material.out", "session.ciphertext.out", Category = "SecondRun")]
        [TestCase("signedsession", "", "signed", "", "signed.session.out", "signed.ciphertext.out",
            Category = "SecondRun")]
        [TestCase("bson_session", "unofficial", "", "bson", "session.out", "ciphertext.out",
            Category = "Unofficial,SecondRun")]
        [TestCase("signed_bson_session", "unofficial", "signed", "bson", "session.out", "ciphertext.out",
            Category = "Unofficial,SecondRun")]
        public void TestCreateSessions(string topDir, string subDir, string signed, string packer,
                                       string sessionFilename, string ciphertextFilename)
        {
            var kspath = Util.TestDataPath(WRITE_DATA, topDir, subDir);
            Directory.CreateDirectory(kspath);

            ISessionKeyPacker keyPacker = null;
            int? keySize = null;
            KeyType keyType = null;
            if (!String.IsNullOrWhiteSpace(packer))
            {
                keyPacker = new BsonSessionKeyPacker();
                keySize = 256;
                keyType = UnofficialKeyType.AesAead;
            }
            using (var encrypter = new Encrypter(Util.TestDataPath(WRITE_DATA, "rsa.public")))
            using (var signer = String.IsNullOrWhiteSpace(signed)
                                    ? null
                                    : new AttachedSigner(Util.TestDataPath(WRITE_DATA, "dsa")))
            using (var session = new SessionCrypter(encrypter, signer, keySize, keyType, keyPacker))
            {
                var material = session.SessionMaterial;

                var ciphertext = session.Encrypt(input);

                File.WriteAllText(Path.Combine(kspath, sessionFilename), material);
                File.WriteAllText(Path.Combine(kspath, ciphertextFilename), ciphertext);
            }
        }

        [Test]
        [Category("Create")]
        [Category("Unofficial")]
        public void TestCreateBlob()
        {
            Directory.CreateDirectory(Util.TestDataPath(WRITE_DATA, ""));

            var keyMetaData = new KeyMetadata
                                  {
                                      Name = "Blob",
                                      Purpose = KeyPurpose.DecryptAndEncrypt,
                                      Kind = KeyKind.Symmetric
                                  };
                                  
            using (var keySet = new MutableKeySet(keyMetaData))
            {
                keySet.AddKey(KeyStatus.Primary, 256);

                using (var stream = File.OpenWrite(Util.TestDataPath(WRITE_DATA, "cryptkey.zip", "unofficial")))
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
                                               Purpose = KeyPurpose.SignAndVerify,
                                               Kind = KeyKind.Private
                                           };
                                           
                    using (var keySet2 = new MutableKeySet(keyMetaData2))
                    {
                        keySet2.AddKey(KeyStatus.Primary);
                        using (var stream2 = File.OpenWrite(Util.TestDataPath(WRITE_DATA, "signkey.zip", "unofficial")))
                        using (var writer2 = new BlobKeySetWriter(stream2))
                        {
                            keySet2.Save(new EncryptedKeySetWriter(writer2, crypt));
                        }

                        using (var signer = new Signer(keySet2))
                        {
                            File.WriteAllText(Util.TestDataPath(WRITE_DATA, "sign.out", "unofficial"),
                                              signer.Sign(input));
                        }
                    }
                }
            }
        }


        private void HelperCryptCreate(IKeySetWriter writer, IKeySet keySet, string kspath, KeyType keyType, 
                                       IKeySet nonEncryptedKS = null, IKeySetWriter nonEncryptedWriter = null)
        {
            using (var ks = new MutableKeySet(nonEncryptedKS ?? keySet))
            {
                var ver = ks.AddKey(KeyStatus.Primary, type: keyType);
                Expect(ver, Is.EqualTo(1));

                var success = ks.Save(nonEncryptedWriter ?? writer);
                Expect(success, Is.True);
            }

            using (var encrypter = new Encrypter(nonEncryptedKS ?? keySet))
            {
                var ciphertext = encrypter.Encrypt(input);
                File.WriteAllText(Path.Combine(kspath, "1.out"), ciphertext);
            }

            using (var ks = new MutableKeySet(keySet))
            {

                var ver = ks.AddKey(KeyStatus.Primary, type: keyType);
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