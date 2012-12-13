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
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
                var badoutput = signedoutput.ToBytes();
                badoutput[10] ^= 9;
                var badlength = new byte[12];
                Array.Copy(badoutput, badlength, badlength.Length);

                Expect(signer.Verify(signedoutput), Is.True);
                Expect(verifier.Verify(signedoutput), Is.True);
            }
        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndVerifyBad(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
				var badoutput = signedoutput.ToBytes();
                badoutput[10] ^= 9;
     
                Expect(signer.Verify(badoutput), Is.False);
                Expect(verifier.Verify(badoutput), Is.False);

            }
        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndVerifyShort(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
                var badoutput = signedoutput.ToBytes();
                badoutput[10] ^= 9;
                var badlength = new byte[12];
                Array.Copy(badoutput, badlength, badlength.Length);

                Expect(() => signer.Verify(badlength), Throws.InstanceOf<InvalidCryptoDataException>());
                Expect(() => verifier.Verify(badlength), Throws.InstanceOf<InvalidCryptoDataException>());

            }
        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndVerifyMessage(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
     
                Expect(signer.VerifiedMessage(signedoutput), Is.EqualTo(input));

                Expect(verifier.VerifiedMessage(signedoutput), Is.EqualTo(input));

            }
        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndTryVerifyMessage(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
                string verifiedOutput; 
                string verifiedOutput2;

                Expect(signer.TryGetVerifiedMessage(signedoutput, out verifiedOutput), Is.True);

                Expect(verifier.TryGetVerifiedMessage(signedoutput, out verifiedOutput2), Is.True);

                Expect(verifiedOutput, Is.EqualTo(input)); 
                
                Expect(verifiedOutput2, Is.EqualTo(input));
            }
        }


        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndVerifyMessageBad(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
                var badoutput = signedoutput.ToBytes();
                badoutput[10] ^= 9;
 
                Expect(() => signer.VerifiedMessage(badoutput), Throws.InstanceOf<InvalidCryptoDataException>());
                Expect(() => verifier.VerifiedMessage(badoutput), Throws.InstanceOf<InvalidCryptoDataException>());

            }
        }


        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndTryVerifyMessageBad(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
                byte[] verifiedOutput;
                byte[] verifiedOutput2;
                var badoutput = signedoutput.ToBytes();
                badoutput[10] ^= 9;

                Expect(signer.TryGetVerifiedMessage(badoutput, out verifiedOutput), Is.False);

                Expect(verifier.TryGetVerifiedMessage(badoutput, out verifiedOutput2), Is.False);

            }
        }


        [TestCase("hmac")]
        [TestCase("dsa")]
        [TestCase("rsa-sign")]
        public void TestSignAndTryVerifyMessageShort(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);
                byte[] verifiedOutput;
                byte[] verifiedOutput2;
                var badoutput = signedoutput.ToBytes();
                badoutput[10] ^= 9;
                var badlength = new byte[12];
                Array.Copy(badoutput, badlength, badlength.Length);

                Expect(signer.TryGetVerifiedMessage(badlength, out verifiedOutput), Is.False);

                Expect(verifier.TryGetVerifiedMessage(badlength, out verifiedOutput2), Is.False);

            }
        }
    }
}
