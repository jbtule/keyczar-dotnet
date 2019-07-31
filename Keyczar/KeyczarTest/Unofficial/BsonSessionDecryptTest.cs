using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Unofficial;
using Keyczar.Util;
using NUnit.Framework;

namespace KeyczarTest.Unofficial
{
    [Category("Unofficial")]
    [TestFixture("gen|cstestdata")]
    public class BsonSessionDecryptTest : BaseHelper
    {
        private readonly String TEST_DATA;

        private String input = "This is some test data";


        private Crypter privateKeyDecrypter;
        private AttachedVerifier publicKeyVerifier;

        [SetUp]
        public void Setup()
        {
            privateKeyDecrypter = new Crypter(Util.TestDataPath(TEST_DATA, "rsa"));
            publicKeyVerifier = new AttachedVerifier(Util.TestDataPath(TEST_DATA, "dsa.public"));
        }

        public BsonSessionDecryptTest(string testPath)
        {
            testPath = Util.ReplaceDirPrefix(testPath);
            TEST_DATA = testPath;
        }

        [TestCase("")]
        [TestCase("signed")]
        public void TestDecrypt(string signed)
        {
            string subDir = "bson_session";
            if (!string.IsNullOrWhiteSpace(signed))
            {
                subDir = "signed_" + subDir;
            }
            else
            {
                publicKeyVerifier = publicKeyVerifier.SafeDispose();
            }
            var subPath = Util.TestDataPath(TEST_DATA, subDir, "unofficial");
            var sessionMaterialInput = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "session.out")).First();

            var sessionCiphertextInput = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "ciphertext.out")).First();

            using (
                var sessionCrypter = new SessionCrypter(privateKeyDecrypter, sessionMaterialInput, publicKeyVerifier,
                                                        new BsonSessionKeyPacker()))
            {
                var plaintext = sessionCrypter.Decrypt(sessionCiphertextInput);
                Expect(plaintext, Is.EqualTo(input));
            }
        }
    }
}