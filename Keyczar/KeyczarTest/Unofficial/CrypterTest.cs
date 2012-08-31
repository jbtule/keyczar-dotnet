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
using Keyczar;
using Keyczar.Util;
using NUnit.Framework;

namespace KeyczarTest.Unofficial
{
    [TestFixture]
    public class CrypterTest:AssertionHelper
    {
        private static readonly String TEST_DATA = Path.Combine("testdata","unofficial");
        private static String input = "This is some test data";
        private static byte[] inputBytes = Encoding.UTF8.GetBytes(input);

        private void HelperDecrypt(String subDir)
        {
            var subPath = Path.Combine(TEST_DATA, subDir);
            using (var crypter = new Crypter(subPath))
            {
                HelperDecrypt(crypter, subDir);
            }
        }

        private void HelperDecrypt(Crypter crypter, String subDir)
        {

            var subPath = Path.Combine(TEST_DATA, subDir);
            String activeCiphertext = File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
            String primaryCiphertext = File.ReadAllLines(Path.Combine(subPath, "2.out")).First();

            String activeDecrypted = crypter.Decrypt(activeCiphertext);
            Expect(activeDecrypted, Is.EqualTo(input));
            String primaryDecrypted = crypter.Decrypt(primaryCiphertext);
            Expect(primaryDecrypted, Is.EqualTo(input));
        }

        private void HelperEncryptDecrypt(String subDir)
        {
                
            var subPath = Path.Combine(TEST_DATA, subDir);
            using (var crypter = new Crypter(subPath))
            {
                var cipher = crypter.Encrypt(input);
                var decrypt =crypter.Decrypt(cipher);
                Expect(decrypt, Is.EqualTo(input));
            }

        }


        private void HelperTestBadCipherText(string subPath)
        {
            using (var crypter = new Crypter(Path.Combine(TEST_DATA, subPath)))
            {
                Expect(() => crypter.Decrypt(new byte[0]), Throws.TypeOf<InvalidCryptoDataException>());
                byte[] ciphertext = crypter.Encrypt(inputBytes);
                // Munge the key hash
                ciphertext[1] ^= 44;
                Expect(() => crypter.Decrypt(ciphertext), Throws.TypeOf<InvalidCryptoDataException>());
                //restore   
                ciphertext[1] ^= 44;
                // Munge the ciphertext
                ciphertext[15] ^= 39;
                Expect(() => crypter.Decrypt(ciphertext), Throws.TypeOf<InvalidCryptoDataException>());
            }
        }

        private void HelperNonRepeating(string subDir)
        {
            var subPath = Path.Combine(TEST_DATA, subDir);
            using (var crypter = new Crypter(subPath))
            {
                var cipher = crypter.Encrypt(input);
                var cipher2 = crypter.Encrypt(input);
                Expect(cipher, Is.Not.EqualTo(cipher2));
            }

        }

        [Test]
        public void TestAesAeadDecrypt()
        {
            HelperDecrypt("aes_aead");
        }

        [Test]
        public void TestAesAeadCryptAndDecrypt()
        {
            HelperEncryptDecrypt("aes_aead");
        }

        [Test]
        public void TestAesAeadEncryptedKeyDecrypt()
        {
            // Test reading and using encrypted keys
            var keyPath = Path.Combine(TEST_DATA, "aes_aead");
            var dataPath = Path.Combine(TEST_DATA, "aes_aead-crypted");
            using (var keyDecrypter = new Crypter(keyPath))
            using (var dataDecrypter = new Crypter(new EncryptedKeySet(dataPath, keyDecrypter)))
            {
                HelperDecrypt(dataDecrypter, "aes_aead-crypted");
            }
        }

          [Test]
        public void TestAesAeadNonRepeating()
        {
            HelperNonRepeating("aes_aead");
        }

        [Test]
        public void TestShortAesAeadEncryptAndDecrypt()
        {
            using (var crypter = new Crypter(Path.Combine(TEST_DATA, "aes_aead")))
            {
                for (int i = 0; i < 32; i++)
                {
                    var letters = Enumerable.Repeat('a', i).ToArray();
                    var each = new String(letters);
                    var ciphertext = crypter.Encrypt(each);
                    var decrypted = crypter.Decrypt(ciphertext);
                    Expect(decrypted, Is.EqualTo(each), "Length:" + i);
                }
            }

        }

        [Test]
        public void TestBadAesAeadCiphertexts()
        {
            HelperTestBadCipherText("aes_aead");
        }
    }
}
