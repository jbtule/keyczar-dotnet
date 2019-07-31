/* 
 * Copyright 2013 James Tuley (jay+code@tuley.name)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
    public class FallbackTest : BaseHelper
    {
        private static String input = "This is some test data";
        private readonly String TEST_DATA = Path.Combine("remote-testdata", "special-case", "badhash");

        /// <summary>
        /// Tests the fall back hash for CPP implementation that stripped leading zeros of the key for hash.
        /// </summary>
        [Test]
        public void TestDecryptCppStrippedLeadingZeros()
        {
            var subPath = Util.TestDataPath(TEST_DATA, "aes-cpp-0");

            using (var crypter = new Crypter(subPath))
            {
                var primaryCipherText = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "1.out")).First();


                var primaryDecrypted = crypter.Decrypt(primaryCipherText);
                Expect(primaryDecrypted, Is.EqualTo(input));
            }
        }

        /// <summary>
        /// Tests the fall back hash for java implementation that used block size instead of keysize for hash
        /// </summary>
        [Test]
        public void TestDecryptJavaBlockSizeHash()
        {
            var subPath = Util.TestDataPath(TEST_DATA, "aes-java-size");

            using (var crypter = new Crypter(subPath))
            {
                var activeCiphertext = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
                var primaryCiphertext = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "2.out")).First();

                var activeDecrypted = crypter.Decrypt(activeCiphertext);
                Expect(activeDecrypted, Is.EqualTo(input));
                var primaryDecrypted = crypter.Decrypt(primaryCiphertext);
                Expect(primaryDecrypted, Is.EqualTo(input));
            }
        }
    }
}