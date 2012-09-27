


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

    [Category("Unofficial")]
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
                var cipherText = (WebBase64) File.ReadAllText(Path.Combine(TEST_DATA, "crypt.out"));
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
                var sig = (WebBase64)File.ReadAllText(Path.Combine(TEST_DATA, "sign.out"));
                Expect(verifier.Verify(input,sig), Is.True);
            }
        }

     
    }
}
