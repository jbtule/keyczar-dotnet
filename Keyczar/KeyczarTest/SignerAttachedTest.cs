using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Unofficial;
using Keyczar.Util;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("rem|dotnet")]
    [TestFixture("gen|cstestdata")]
    [TestFixture("gen|tool_cstestdata")]
    public class SignerAttachedTest : AssertionHelper
    {
        private readonly String TEST_DATA;
        private static String input = "This is some test data";
        private static string jsonInput = "{\"sub\": \"1234567890\",\"name\": \"John Doe\",\"admin\": true}";

        public SignerAttachedTest(string testPath)
        {
            testPath = Util.ReplaceDirPrefix(testPath);

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

        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndVerify(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);

                Expect(signer.Verify(signedoutput), Is.True);
                Expect(verifier.Verify(signedoutput), Is.True);
            }
        }
        
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndVerifyJwt(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
            using (var ks = new FileSystemKeySet(subPath))
            using (var signer = new JwtSigner(ks))
            using (var verifier = new JwtVerifier(ks))
            {
                var signedoutput = signer.SignCompact(JObject.Parse(jsonInput));

                Console.WriteLine(signedoutput);
                Expect(verifier.VerifyCompact(signedoutput), Is.True);
                
                Expect(signer.VerifyCompact(signedoutput), Is.True);

            }
        }



        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndVerifyBad(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
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

        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndVerifyShort(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
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

        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndVerifyMessage(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
            using (var signer = new AttachedSigner(subPath))
            using (var verifier = new AttachedVerifier(subPath))
            {
                var signedoutput = signer.Sign(input);

                Expect(signer.VerifiedMessage(signedoutput), Is.EqualTo(input));

                Expect(verifier.VerifiedMessage(signedoutput), Is.EqualTo(input));
            }
        }

        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndTryVerifyMessage(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
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


        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndVerifyMessageBad(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
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

        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndTryVerifyMessageBad(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
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


        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        [TestCase("hmac_sha2", "unofficial")]
        public void TestSignAndTryVerifyMessageShort(String subDir, string nestDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
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