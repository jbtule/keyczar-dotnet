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

/**
 * These tests read keys that were exported from a reference implementation.
 * It will be used to ensure that this Keyczar implementation is
 * cross-compatible. 
 *
 * @author steveweis@gmail.com (Steve Weis)
 * 
 * 9/2012 Direct ported to c# jay+code@tuley.name (James Tuley)
 * 
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture]
    public class CrossCompatibilityTest:AssertionHelper
    {
        private static readonly String TEST_DATA = Path.Combine("testdata","crosscomp");
        private String plaintext = "This is not a test, this is a real string";
        private String morePlaintext = "Some text to encrypt";

        [TestCase("aes")]
        public void TestDecryptPrimaryActive(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var crypter = new Crypter(subPath))
            {
                String activeCiphertext = File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
                String primaryCiphertext = File.ReadAllLines(Path.Combine(subPath, "2.out")).First();
                
                String activeDecrypted = crypter.Decrypt(activeCiphertext);
                Expect(activeDecrypted, Is.EqualTo(morePlaintext));
                String primaryDecrypted = crypter.Decrypt(primaryCiphertext);
                Expect(primaryDecrypted, Is.EqualTo(plaintext));
            }
        }

        [TestCase("rsa")]
        public void TestDecryptPrimaryOnly(String subDir)
        {

            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var crypter = new Crypter(subPath))
            {
                String primaryCiphertext = File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
                String primaryDecrypted = crypter.Decrypt(primaryCiphertext);
                Expect(primaryDecrypted, Is.EqualTo(plaintext));
            }
        }

        [TestCase("hmac")]
        [TestCase("dsa")]
        public void TestVerify(String subDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir);
            using (var verifier = new Signer(subPath))
            {
                String signature = File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
                Expect(verifier.Verify(plaintext, signature), Is.True);
            }
        }



    }
}
