using System;
using System.IO;
using System.Linq;
using Keyczar;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("testdata")]
    [TestFixture("cstestdata")]
    public class SessionDecryptTest:AssertionHelper
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

        public SessionDecryptTest(string testPath)
        {
            TEST_DATA = testPath;
        }

        [Test]
        public void TestSignedDecrypt()
        {
            var subPath = Util.TestDataPath(TEST_DATA, "signedsession");
            var sessionMaterialInput = (WebBase64)File.ReadAllLines(Path.Combine(subPath, "signed.session.out")).First();

            var sessionCiphertextInput = (WebBase64)File.ReadAllLines(Path.Combine(subPath, "signed.ciphertext.out")).First();

            using (var sessionCrypter = new SessionCrypter(privateKeyDecrypter, sessionMaterialInput, publicKeyVerifier))
            {
                var plaintext = sessionCrypter.Decrypt(sessionCiphertextInput);
                Expect(plaintext, Is.EqualTo(input));
            }

        }

        [Test]
        public void TestDecrypt()
        {
            var subPath = Util.TestDataPath(TEST_DATA, "rsa");
            var sessionMaterialInput = (WebBase64)File.ReadAllLines(Path.Combine(subPath, "session.material.out")).First();

            var sessionCiphertextInput = (WebBase64)File.ReadAllLines(Path.Combine(subPath, "session.ciphertext.out")).First();

            using (var sessionCrypter = new SessionCrypter(privateKeyDecrypter, sessionMaterialInput))
            {
                var plaintext = sessionCrypter.Decrypt(sessionCiphertextInput);
                Expect(plaintext, Is.EqualTo(input));
            }

        }
    }
}