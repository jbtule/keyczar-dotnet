/*
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
 * Tests PkcsKeyReader.
 *
 * @author swillden@google.com (Shawn Willden)
 * 
 * 9/2012 ported to c# jay+code@tuley.name (James Tuley)
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
    public class PkcsImportTest:AssertionHelper
    {
          private static readonly String TEST_DATA = Path.Combine("testdata","certificates");
          private static readonly String[] FILE_FORMATS = { "der", "pem" };
          private static readonly String[] KEY_TYPES = { "dsa", "rsa"};
          private static readonly String input = "This is some test data";

          private Stream HelperOpenPkcsStream(String keyType, String fileFormat, String keyPurpose)
          {
              return File.OpenRead(Path.Combine(TEST_DATA, keyType + "-" + keyPurpose + "-pkcs8." + fileFormat));
          }

          private void HelperCryptImport(Stream keystream)
          {
              using (var keyset = ImportedKeySet.Import.PkcsKey(KeyPurpose.DECRYPT_AND_ENCRYPT, keystream, "pass"))
              using (var crypter = new Crypter(keyset))
              using (var encrypter = new Encrypter(Path.Combine(TEST_DATA, "rsa-crypt")))
              {

                  String ciphertext = encrypter.Encrypt(input);
                  String plaintext = crypter.Decrypt(ciphertext);
                  Expect(plaintext, Is.EqualTo(input));
              }
          }

          private void HelperSignImport(String keyType, Stream keystream)
          {
              using (var keyset = ImportedKeySet.Import.PkcsKey(KeyPurpose.SIGN_AND_VERIFY, keystream, "pass"))
              using (var signer = new Signer(keyset))
          
              {
                  String signature = signer.Sign(input);
                  using (var verifier = new Verifier(Path.Combine(TEST_DATA, keyType + "-sign-pub")))
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
                using (var stream = HelperOpenPkcsStream("rsa", format, "crypt"))
                {
                    HelperCryptImport(stream);
                }
            }
        }

        [Test]
        public void TestSignImport()
        {
            foreach (var keyType in KEY_TYPES)
            {
                foreach (var format in FILE_FORMATS)
                {
                    using (var stream = HelperOpenPkcsStream(keyType, format, "sign"))
                    {
                        HelperSignImport(keyType,stream);
                    }
                }
            }
        }
    }
}
