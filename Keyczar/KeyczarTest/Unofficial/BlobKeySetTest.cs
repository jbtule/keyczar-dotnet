using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Unofficial;
using NUnit.Framework;
using Keyczar;

namespace KeyczarTest.Unofficial
{
    [TestFixture]
    public class BlobKeySetTest : AssertionHelper
    {
        private static string input = "Some test text";
        private static string TEST_DATA = Path.Combine("testdata", "unofficial", "blob");

        [Test]
        public void TestDecrypt()
        {
            using (var stream = File.OpenRead(Path.Combine(TEST_DATA,"cryptkey.zip")))
            using( var keySet = new BlobKeySet(stream))
            using(var crypter = new Crypter(keySet))
            {
                var cipherText = File.ReadAllText(Path.Combine(TEST_DATA, "crypt.out"));
                Expect(crypter.Decrypt(cipherText),Is.EqualTo(input));
            }
        }

        [Test]
        public void TestSign()
        {
            using (var stream = File.OpenRead(Path.Combine(TEST_DATA, "cryptkey.zip")))
            using (var keySet = new BlobKeySet(stream))
            using (var crypter = new Crypter(keySet))
            using (var signstream = File.OpenRead(Path.Combine(TEST_DATA, "signkey.zip")))
            using (var signkeySet = new BlobKeySet(signstream))
            using (var verifier = new Verifier(new EncryptedKeySet(signkeySet,crypter)))
            {
                var sig = File.ReadAllText(Path.Combine(TEST_DATA, "sign.out"));
                Expect(verifier.Verify(input,sig), Is.True);
            }
        }

        [Test]
        public void TestCreateBlob()
        {
           Assert.Ignore("Used to create test data.");
            var keyMetaData = new KeyMetadata
                                  {
                                      Name = "Blob",
                                      Purpose = KeyPurpose.DECRYPT_AND_ENCRYPT,
                                      Type=KeyType.AES
                                  };
            using (var keySet = new MutableKeySet(keyMetaData))
            {
                keySet.AddKey(KeyStatus.PRIMARY, 256);

                using(var stream = File.OpenWrite("cryptkey.zip"))
                using(var writer =  new BlobKeySetWriter(stream))
                {
                    keySet.Save(writer);
                }

                using(var crypt = new Crypter(keySet))
                {
                    File.WriteAllText("crypt.out",crypt.Encrypt(input));
                    var keyMetaData2 = new KeyMetadata
                                           {
                                               Name = "Blob",
                                               Purpose = KeyPurpose.SIGN_AND_VERIFY,
                                               Type = KeyType.RSA_PRIV
                                           };
                    using (var keySet2 = new MutableKeySet(keyMetaData2))
                    {
                        keySet2.AddKey(KeyStatus.PRIMARY);
                        using (var stream2 = File.OpenWrite("signkey.zip"))
                        using(var writer2 = new BlobKeySetWriter(stream2))
                        {
                            keySet2.Save(new EncryptedKeySetWriter(writer2,crypt));
                        }

                        using(var  signer = new Signer(keySet2))
                        {
                            File.WriteAllText("sign.out",signer.Sign(input));
                        }
                    }
                }


            }


        }
    }
}
