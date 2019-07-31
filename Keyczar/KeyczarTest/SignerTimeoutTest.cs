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
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Keyczar;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("rem|dotnet")]
    [TestFixture("gen|cstestdata")]
    [TestFixture("gen|tool_cstestdata")]
    public class SignerTimeoutTest : BaseHelper
    {
        private readonly String TEST_DATA;

        public SignerTimeoutTest(string testPath)
        {
            testPath = Util.ReplaceDirPrefix(testPath);

            TEST_DATA = testPath;
        }


        private String input = "This is some test data";

        [TestCase("aes", "")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestWrongPurpose(String subDir, string nestdir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestdir);
            Expect(() => new TimeoutSigner(subPath), Throws.InstanceOf<InvalidKeySetException>());
            Expect(() => new TimeoutVerifier(subPath), Throws.InstanceOf<InvalidKeySetException>());
        }


        [TestCase("hmac", "")]
        [TestCase("dsa", "")]
        [TestCase("rsa-sign", "")]
        [TestCase("rsa-sign", "unofficial")]
        public void TestTimeoutSignAndVerify(string subPath, string nestDir)
        {
            using (var signer = new TimeoutSigner(Util.TestDataPath(TEST_DATA, subPath, nestDir)))
            using (var verifier = new TimeoutVerifier(Util.TestDataPath(TEST_DATA, subPath, nestDir)))
            {
                // Create a signature that will be valid for a long time
                var sig = signer.Sign(input, DateTime.Now.AddDays(365));
                Expect(signer.Verify(input, sig), Is.True);
                Expect(verifier.Verify(input, sig), Is.True);

                // Create a signature that is already expired
                sig = signer.Sign(input, DateTime.Now.AddDays(-1));
                Expect(signer.Verify(input, sig), Is.False);
                Expect(verifier.Verify(input, sig), Is.False);

                // Create a valid signature, let it expire, and check that it is now invalid
                var nearExpiration = DateTime.Now.AddSeconds(5);
                sig = signer.Sign(input, nearExpiration);
                Expect(verifier.Verify(input, sig), Is.True);
                while (DateTime.Now < nearExpiration)
                {
                    Thread.Sleep(1000);
                }
                Expect(verifier.Verify(input, sig), Is.False);
            }
        }
    }
}