using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Util;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("testdata")]
    [TestFixture("cstestdata")]
    [TestFixture("tool_cstestdata")]
    public class SignerAttachedTest:AssertionHelper
    {        
        private readonly String TEST_DATA;
        private static String input = "This is some test data";

        public SignerAttachedTest(string testPath)
          {
              TEST_DATA = testPath;
        }

        [TestCase("aes", "")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestWrongPurpose(String subDir, string nestdir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestdir);
            Expect(() => new AttachedSigner(subPath), Throws.InstanceOf<InvalidKeySetException>());
            Expect(() => new AttachedVerifier(subPath), Throws.InstanceOf<InvalidKeySetException>());

        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndVerify(String subDir)
        {
            using (var signer = new AttachedSigner(Path.Combine(TEST_DATA, subDir)))
            using (var verifier = new AttachedVerifier(Path.Combine(TEST_DATA, subDir)))
            {
                String signedoutput = signer.Sign(input);
                var badoutput = WebSafeBase64.Decode(signedoutput.ToCharArray());
                badoutput[10] ^= 9;
                var badlength = new byte[12];
                Array.Copy(badoutput, badlength, badlength.Length);

                Expect(signer.Verify(signedoutput), Is.True);
                Expect(signer.Verify(badoutput), Is.False);
                Expect(()=>signer.Verify(badlength), Throws.InstanceOf<InvalidCryptoDataException>());

                Expect(verifier.Verify(signedoutput), Is.True);
                Expect(verifier.Verify(badoutput), Is.False);
                Expect(() => verifier.Verify(badlength), Throws.InstanceOf<InvalidCryptoDataException>());
            }
        }
    }
}
