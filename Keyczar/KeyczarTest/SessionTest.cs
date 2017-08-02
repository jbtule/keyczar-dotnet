/*
 * Copyright 2010 Google Inc.
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
using System.Text;
using Keyczar;
using Keyczar.Unofficial;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("rem|dotnet")]
    [TestFixture("gen|cstestdata")]
    [TestFixture("gen|tool_cstestdata")]
    public class SessionTest : AssertionHelper
    {
        private readonly String TEST_DATA;

        public SessionTest(string testPath)
        {
            testPath = Util.ReplaceDirPrefix(testPath);

            TEST_DATA = testPath;
        }

        private static String input = "This is some test data";

        // Bigger than a public key block
        private byte[] bigInput = new byte[10000];
        private Encrypter publicKeyEncrypter;
        private Crypter privateKeyDecrypter;

        [SetUp]
        public void Setup()
        {
            publicKeyEncrypter = new Encrypter(Util.TestDataPath(TEST_DATA, "rsa.public"));
            privateKeyDecrypter = new Crypter(Util.TestDataPath(TEST_DATA, "rsa"));
        }

        private SessionCrypter HelperSessionCrypter(Encrypter encrypter, string unoffical)
        {
            if (String.IsNullOrWhiteSpace(unoffical))
            {
                return new SessionCrypter(encrypter);
            }
            else
            {
                return new SessionCrypter(encrypter, symmetricKeyType: UnofficialKeyType.AesAead,
                                          keyPacker: new BsonSessionKeyPacker());
            }
        }

        private SessionCrypter HelperSessionCrypter(Crypter crypter, WebBase64 session, string unoffical)
        {
            if (String.IsNullOrWhiteSpace(unoffical))
            {
                return new SessionCrypter(crypter, session);
            }
            else
            {
                return new SessionCrypter(crypter, session, keyPacker: new BsonSessionKeyPacker());
            }
        }

        [TestCase("")]
        [TestCase("bson", Category = "Unofficial")]
        public void TestCrypterDecryptsOwnCiphertext(string unoffical)
        {
            using (var sessionCrypter = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            {
                var ciphertext = sessionCrypter.Encrypt(input);


                var plaintext = sessionCrypter.Decrypt(ciphertext);
                Expect(plaintext, Is.EqualTo(input));

                // Try encrypting a bigger input under the same session key
                byte[] bigCiphertext = sessionCrypter.Encrypt(bigInput);
                byte[] bigPlaintext = sessionCrypter.Decrypt(bigCiphertext);
                Expect(bigPlaintext, Is.EqualTo(bigInput));
            }


            //If you close the session and start again, you'd get a different crypter key
            WebBase64 ciphertext2;
            using (var sessionCrypter = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            {
                ciphertext2 = sessionCrypter.Encrypt(input);
            }

            using (var sessionCrypter = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            {
                Expect(() => sessionCrypter.Decrypt(ciphertext2), Throws.InstanceOf<InvalidCryptoDataException>());
            }
        }

        [TestCase("")]
        [TestCase("bson", Category = "Unofficial")]
        public void TestCrypterPair(string unoffical)
        {
            using (var localCrypter = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            {
                var encrypted = localCrypter.Encrypt(input);
                var sessionMaterial = localCrypter.SessionMaterial;

                using (var remoteCrypter = HelperSessionCrypter(privateKeyDecrypter, sessionMaterial, unoffical))
                {
                    var decrypted = remoteCrypter.Decrypt(encrypted);
                    Expect(decrypted, Is.EqualTo(input));

                    var encryptedB = remoteCrypter.Encrypt(bigInput);
                    var decryptedB = localCrypter.Decrypt(encryptedB);
                    Expect(decryptedB, Is.EqualTo(bigInput));
                }
            }
        }

        [TestCase("")]
        [TestCase("bson", Category = "Unofficial")]
        public void TestWrongSession(string unoffical)
        {
            using (var localCrypter = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            using (var localCrypter2 = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            {
                var encrypted = localCrypter.Encrypt(input);
                var sessionMaterial = localCrypter2.SessionMaterial;

                using (var remoteCrypter = HelperSessionCrypter(privateKeyDecrypter, sessionMaterial, unoffical))
                {
                    Expect(() => remoteCrypter.Decrypt(encrypted), Throws.TypeOf<InvalidCryptoDataException>());
                }
            }
        }
    }
}