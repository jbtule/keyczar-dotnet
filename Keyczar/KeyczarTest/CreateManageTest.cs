using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
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
        [TestCase("c#_aes_aead", "aes_aead", "unofficial")]
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
			Func<string> passPrompt = ()=>"pass"; //hardcoded because this is a test;
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

            var kspath2 = Util.TestDataPath(WRITE_DATA, topDir+".public");
            var writer2 = new KeySetWriter(kspath2, overwrite: true);
            using (var ks = new MutableKeySet(kspath))
            {
                var pubKs = ks.PublicKey();
                var success = pubKs.Save(writer2);
                Expect(success, Is.True);
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
