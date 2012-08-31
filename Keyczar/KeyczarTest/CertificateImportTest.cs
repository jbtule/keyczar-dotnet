 /*
 *
 * Copyright 2011 Google Inc.
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
 * Tests of X.509 certificate import functionality.
 *
 * @author swillden@google.com (Shawn Willden)
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
using Keyczar.Compat;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture]
    public class CertificateImportTest:AssertionHelper
    {
          private static readonly String TEST_DATA = Path.Combine("testdata","certificates");
          private static readonly String[] FILE_FORMATS = { "pem", "der" };
          private static readonly String[] KEY_TYPES = { "rsa", "dsa" };
          private String input = "This is some test data";

        private void HelperCryptImport(String fileFormat){

            using(var keyset = ImportedKeySet.Import.X509Certificate(KeyPurpose.ENCRYPT,Path.Combine(TEST_DATA , "rsa-crypt-crt." +fileFormat)))
            using(var encrypter = new Encrypter(keyset))
            using (var crypter = new Crypter(Path.Combine(TEST_DATA, "rsa-crypt")))
            {

                String ciphertext = encrypter.Encrypt(input);
                String plaintext = crypter.Decrypt(ciphertext);
                Expect(plaintext, Is.EqualTo(input));
            }
        }

        private void HelperSignImport(String keyType, String fileFormat)
        {
             using (var signer = new Signer(Path.Combine(TEST_DATA, keyType + "-sign")))
             {
                 String signature = signer.Sign(input);
                 using (var keyset = ImportedKeySet.Import.X509Certificate(KeyPurpose.VERIFY, Path.Combine(TEST_DATA, keyType + "-sign-crt." + fileFormat)))
                 using (var verifier = new Verifier(keyset))
                 {
                     Expect(verifier.Verify(input, signature), Is.True);
                 }
             }
         }
        [Test]
        public void TestCryptImport()
        {
            foreach (var format in FILE_FORMATS)
            {
                HelperCryptImport(format);
            }
        }

        [Test]
        public void TestSignImport()
        {
            foreach (var format in FILE_FORMATS)
            {
                foreach (var keyType in KEY_TYPES)
                {
                    HelperSignImport(keyType,format);
                }
            }
        }
    }
}
