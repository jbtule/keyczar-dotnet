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
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Unofficial;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture("testdata")]
    [TestFixture("cstestdata")]
    [TestFixture("tool_cstestdata")]
    public class SessionTest:AssertionHelper
    {

          private readonly String TEST_DATA;

          public SessionTest(string testPath)
          {
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
            publicKeyEncrypter = new Encrypter(Path.Combine(TEST_DATA, "rsa.public"));
            privateKeyDecrypter = new Crypter(Path.Combine(TEST_DATA, "rsa"));
        }

        private SessionCrypter HelperSessionCrypter(Encrypter encrypter,string unoffical)
        {
            if (String.IsNullOrWhiteSpace(unoffical))
            {
                return new SessionCrypter(encrypter);
            }else
            {
                return new SessionCrypter(encrypter, symmetricKeyType: KeyType.AES_AEAD, keyPacker: new BsonSessionKeyPacker());
            }
        }

        private SessionCrypter HelperSessionCrypter(Crypter crypter, byte[] session, string unoffical)
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
       public  void TestCrypterDecryptsOwnCiphertext(string unoffical){
           using (var sessionCrypter = HelperSessionCrypter(publicKeyEncrypter,unoffical))
           {
               var ciphertext = sessionCrypter.Encrypt(input);


               var plaintext = sessionCrypter.Decrypt(ciphertext);
               Expect(plaintext, Is.EqualTo(input));

               // Try encrypting a bigger input under the same session key
               byte[] bigCiphertext = sessionCrypter.Encrypt(bigInput);
               byte[] bigPlaintext = sessionCrypter.Decrypt(bigCiphertext);
               Expect(bigPlaintext, Is.EqualTo(bigInput));
           }
       }

        [TestCase("")]
        [TestCase("bson", Category = "Unofficial")]
         public void TestCrypterPair(string unoffical)
        {
            using (var localCrypter = HelperSessionCrypter(publicKeyEncrypter, unoffical))
            {
                var encrypted = localCrypter.Encrypt(input);
                byte[] sessionMaterial = localCrypter.SessionMaterial;

                using (var remoteCrypter = HelperSessionCrypter(privateKeyDecrypter, sessionMaterial, unoffical))
                {

                    var decrypted = remoteCrypter.Decrypt(encrypted);
                    Expect(decrypted,Is.EqualTo(input));

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
                  byte[] sessionMaterial = localCrypter2.SessionMaterial;

                  using (var remoteCrypter = HelperSessionCrypter(privateKeyDecrypter, sessionMaterial, unoffical))
                  {
                      Expect(() => remoteCrypter.Decrypt(encrypted), Throws.TypeOf<InvalidCryptoDataException>());
                  }
              }
          }
    }
}
