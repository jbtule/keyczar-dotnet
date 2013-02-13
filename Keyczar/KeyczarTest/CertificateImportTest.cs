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

          private String input = "This is some test data";

          [Test]
          public void TestCryptImport([Values("rsa")]String keyType, [Values("pem", "der")]String fileFormat)
          {

            using(var keyset = ImportedKeySet.Import.X509Certificate(KeyPurpose.Encrypt, Util.TestDataPath(TEST_DATA , keyType+"-crypt-crt." +fileFormat)))
            using(var encrypter = new Encrypter(keyset))
            using (var crypter = new Crypter(Util.TestDataPath(TEST_DATA, "rsa-crypt")))
            {

                var ciphertext = encrypter.Encrypt(input);
                var plaintext = crypter.Decrypt(ciphertext);
                Expect(plaintext, Is.EqualTo(input));
            }
        }
             
        
         [Test]
          public void TestSignImport([Values("rsa", "dsa")]String keyType, [Values("pem", "der")] String fileFormat)
        {
            using (var signer = new Signer(Util.TestDataPath(TEST_DATA, keyType + "-sign")))
             {
                 var signature = signer.Sign(input);
                 using (var keyset = ImportedKeySet.Import.X509Certificate(KeyPurpose.Verify, Util.TestDataPath(TEST_DATA, keyType + "-sign-crt." + fileFormat)))
                 using (var verifier = new Verifier(keyset))
                 {
                     Expect(verifier.Verify(input, signature), Is.True);
                 }
             }
         }
   

    }
}
