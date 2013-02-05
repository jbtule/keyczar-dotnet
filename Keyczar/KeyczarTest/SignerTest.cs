
/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * 
 * 8/2012 directly ported to c# - jay+code@tuley.name (James Tuley)
 * 
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Compat;
using NUnit.Framework;
using Keyczar;
namespace KeyczarTest
{
    [TestFixture("testdata")]
    [TestFixture("cstestdata")]
    [TestFixture("tool_cstestdata")]
    public class SignerTest:AssertionHelper
    {
           
          private readonly String TEST_DATA;

          public SignerTest(string testPath)
          {
              TEST_DATA = testPath;
          }



        private static String input = "This is some test data";
        private static byte[] inputBytes = Encoding.UTF8.GetBytes(input);

        [TestCase("hmac")]
        public void TestSignerVerify(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var verifier = new Signer(subPath))
            {
                var activeSignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
				var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "2.out")).First();
                Expect(verifier.Verify(input, activeSignature), Is.True);
                Expect(verifier.Verify(input, primarySignature), Is.True);
            }
        }


        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
         public void TestPublicVerify(String subDir, string nestDir)
         {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);

            using (var verifier = new Verifier(subPath))
            using (var publicVerifier = new Verifier(subPath + ".public"))
            {
                var activeSignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
				var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "2.out")).First();

                Expect(verifier.Verify(input, activeSignature), Is.True);
                Expect(verifier.Verify(input, primarySignature), Is.True);
                Expect(publicVerifier.Verify(input, activeSignature), Is.True);
                Expect(publicVerifier.Verify(input, primarySignature), Is.True);
            }
         }

         [TestCase("hmac", "")]
         [TestCase("dsa", "")]
         [TestCase("rsa-sign", "")]
         [TestCase("rsa-sign", "unofficial")]
         public void TestBadVerify(String subDir, string nestDir)
         {
             var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
             using (var verifier = new Signer(subPath))
             {
                 var activeSignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
                 var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "2.out")).First();
                 Expect(verifier.Verify("Wrong String", activeSignature), Is.False);
                 Expect(verifier.Verify("Wrong String", primarySignature), Is.False);
                 Expect(verifier.Verify(input, (WebBase64)(primarySignature.ToString().Substring(0, primarySignature.ToString().Length - 4) + "junk")), Is.False);
             }
         }


         [TestCase("aes", "")]
         [TestCase("rsa", "")]
         [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
         public void TestWrongPurpose(String subDir, string nestdir)
         {
             var subPath = Util.TestDataPath(TEST_DATA, subDir, nestdir);
             Expect(() => new Signer(subPath), Throws.InstanceOf<InvalidKeySetException>());
             Expect(() => new Verifier(subPath), Throws.InstanceOf<InvalidKeySetException>());

         }

         [TestCase("hmac", "")]
         [TestCase("dsa", "")]
         [TestCase("rsa-sign", "")]
         [TestCase("rsa-sign", "unofficial")]
         public void TestSignAndVerify(String subDir, string nestDir)
         {
             var subPath = Util.TestDataPath(TEST_DATA, subDir, nestDir);
             using (var signer = new Signer(subPath))
            {
                var sig = signer.Sign(input);

                Expect(signer.Verify(input, sig), Is.True);
                Expect(signer.Verify("Wrong string", sig), Is.False);
            }
        }





         [TestCase("hmac", "")]
         [TestCase("dsa", "")]
         [TestCase("rsa-sign", "")]
         [TestCase("rsa-sign", "unofficial")]
        public void TestBadSigs(String subDir, string nestDir)
        {
            using (var signer = new Signer(Util.TestDataPath(TEST_DATA, subDir, nestDir)))
            {
                byte[] sig = signer.Sign(inputBytes);

                // Another input string should not verify
                Assert.That(signer.Verify(Encoding.UTF8.GetBytes("Some other string"),sig),Is.False);
                Expect(() => signer.Verify(inputBytes, new byte[0]), Throws.TypeOf<InvalidCryptoDataException>());
                sig[0] ^= 23;
                Expect(() => signer.Verify(inputBytes, sig), Throws.TypeOf<InvalidCryptoVersionException>());
                Expect(() => signer.Verify(inputBytes, sig), Throws.TypeOf<InvalidCryptoVersionException>());
                sig[0] ^= 23;
                sig[1] ^= 45;
                Expect(signer.Verify(inputBytes, sig),Is.False);
            }
        }
    }
}
