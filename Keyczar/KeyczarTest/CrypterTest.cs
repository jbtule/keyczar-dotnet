﻿/*
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

namespace KeyczarTest
{
    [TestFixture]
    public class CrypterTest:AssertionHelper
    {
        private static readonly String TEST_DATA = "testdata";
        private static String input = "This is some test data";
        private static byte[] inputBytes = Encoding.UTF8.GetBytes(input);

        private void HelperDecrypt(Crypter crypter, String subPath)
        {
            String activeCiphertext = File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
            String primaryCiphertext = File.ReadAllLines(Path.Combine(subPath, "2.out")).First();

            String activeDecrypted = crypter.Decrypt(activeCiphertext);
            Expect(activeDecrypted, Is.EqualTo(input));
            String primaryDecrypted = crypter.Decrypt(primaryCiphertext);
            Expect(primaryDecrypted, Is.EqualTo(input));
        }


        [TestCase("aes","")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestDecrypt(String subDir,string nestedDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestedDir);

            using (var crypter = new Crypter(subPath))
            {
                HelperDecrypt(crypter, subPath);
            }
        }

        [TestCase("aes", "")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestEncryptDecrypt(String subDir, string nestedDir)
        {

            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestedDir);

            using (var crypter = new Crypter(subPath))
            {
                var cipher = crypter.Encrypt(input);
                var decrypt =crypter.Decrypt(cipher);
                Expect(decrypt, Is.EqualTo(input));
            }

        }

        [TestCase("aes", "")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestBadCipherText(string subDir, string nestedDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestedDir);

            using (var crypter = new Crypter(subPath))
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



        [Test]
        public void TestRsaCryptWithPublicKey()
        {
            using (var encrypter = new Encrypter(Util.TestDataPath(TEST_DATA, "rsa.public")))
            {
                var cipher = encrypter.Encrypt(input);
                var subPath = Path.Combine(TEST_DATA, "rsa");
                using (var crypter = new Crypter(subPath))
                {
                    var decrypt = crypter.Decrypt(cipher);
                    Expect(decrypt, Is.EqualTo(input));
                }
            }
        }


        [TestCase("aes", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestAesEncryptedKeyDecrypt(string subDir, string nestedDir)
        {
            // Test reading and using encrypted keys




            var basePath = Util.TestDataPath(TEST_DATA, nestedDir);
            var keyPath = Path.Combine(basePath, subDir);
            var dataPath = Path.Combine(basePath, subDir + "-crypted");
            using (var keyDecrypter = new Crypter(keyPath))
            using (var dataDecrypter = new Crypter(new EncryptedKeySet(dataPath, keyDecrypter)))
            {
                HelperDecrypt(dataDecrypter, dataPath);
            }
        }

        [TestCase("aes", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestAesNonRepeating(string subDir, string nestedDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestedDir);

            using (var crypter = new Crypter(subPath))
            {
                var cipher = crypter.Encrypt(input);
                var cipher2 = crypter.Encrypt(input);
                Expect(cipher, Is.Not.EqualTo(cipher2));
            }
        }


        [TestCase("aes", "")]
        [TestCase("rsa", "")]
        [TestCase("aes_aead", "unofficial", Category = "Unofficial")]
        public void TestShortEncryptAndDecrypt(string subDir, string nestedDir)
        {
            var subPath = Util.TestDataPath(TEST_DATA, subDir, nestedDir);
            using (var crypter = new Crypter(subPath))
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

       
    }
}