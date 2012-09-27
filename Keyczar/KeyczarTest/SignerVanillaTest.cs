using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Compat;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("testdata")]
    [TestFixture("cstestdata")]
    [TestFixture("tool_cstestdata")]
    public class SignerVanillaTest:AssertionHelper
    {
        private static String input = "This is some test data";
        private readonly String TEST_DATA;

        public SignerVanillaTest(string testPath)
        {
              TEST_DATA = testPath;
        }

        [TestCase("aes", "")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestWrongPurpose(String subDir, string nestdir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestdir);
            Expect(() => new VanillaSigner(subPath), Throws.InstanceOf<InvalidKeySetException>());
            Expect(() => new VanillaVerifier(subPath), Throws.InstanceOf<InvalidKeySetException>());

        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndVerify(String subDir)
        {
            using (var signer = new VanillaSigner(Path.Combine(TEST_DATA, subDir)))
            using (var verifier = new VanillaVerifier(Path.Combine(TEST_DATA, subDir)))
            {
                var sig = signer.Sign(input);

                Expect(signer.Verify(input, sig), Is.True);
                Expect(signer.Verify("Wrong string", sig), Is.False);

                Expect(verifier.Verify(input, sig), Is.True);
                Expect(verifier.Verify("Wrong string", sig), Is.False);
            }
        }
    }
}
