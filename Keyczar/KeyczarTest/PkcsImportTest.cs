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
    public class PkcsImportTest : AssertionHelper
    {
        private static readonly String TEST_DATA = Path.Combine("remote-testdata", "existing-data", "dotnet",
                                                                "certificates");

        private static readonly String input = "This is some test data";

        private Stream HelperOpenPkcsStream(String keyType, String fileFormat, String keyPurpose)
        {
            return fileFormat == "pfx"
                ? File.OpenRead(Util.TestDataPath(TEST_DATA, keyType + "-" + keyPurpose + "-pkcs12." + fileFormat))
                : File.OpenRead(Util.TestDataPath(TEST_DATA, keyType + "-" + keyPurpose + "-pkcs8." + fileFormat));
        }

        private ImportedKeySet HelperImportKeySet(String fileFormat, KeyPurpose keyPurpose, Stream keystream)
        {
            switch (fileFormat)
            {
                case "pfx":
                    return ImportedKeySet.Import.Pkcs12Keys(keyPurpose, keystream, () => "pass"
                                                         /* hard coding for test only!!!!*/);
                default:
                    return ImportedKeySet.Import.PkcsKey(keyPurpose, keystream, () => "pass"
                                                       /* hard coding for test only!!!!*/);
            }
        }


        [Test]
        public void TestCryptImport(
            [Values("rsa")] string keyType,
            [Values("pem", "der", "pfx")] string format)
        {
            using (var keystream = HelperOpenPkcsStream(keyType, format, "crypt"))
            using (var keyset = HelperImportKeySet(format, KeyPurpose.DecryptAndEncrypt, keystream))
            using (var crypter = new Crypter(keyset))
            using (var encrypter = new Encrypter(Util.TestDataPath(TEST_DATA, "rsa-crypt")))
            {
                var ciphertext = encrypter.Encrypt(input);
                var plaintext = crypter.Decrypt(ciphertext);
                Expect(plaintext, Is.EqualTo(input));
            }
        }

        [Test]
        public void TestCryptImportBadKey(
            [Values("dsa")] string keyType,
            [Values("pem", "der", "pfx")] string format)
        {
            using (var keystream = HelperOpenPkcsStream(keyType, format, "sign"))
            {
                Expect(() => HelperImportKeySet(format, KeyPurpose.DecryptAndEncrypt, keystream),
                       Throws.InstanceOf<InvalidKeySetException>());

            }
        }

        [Test]
        public void TestSignImport(
            [Values("rsa", "dsa")] string keyType,
            [Values("pem", "der", "pfx")] string format)
        {
            using (var keystream = HelperOpenPkcsStream(keyType, format, "sign"))
            using (
                var keyset = HelperImportKeySet(format, KeyPurpose.SignAndVerify, keystream))
            using (var signer = new Signer(keyset))

            {
                var signature = signer.Sign(input);
                using (var verifier = new Verifier(Util.TestDataPath(TEST_DATA, keyType + "-sign-pub")))
                {
                    Expect(verifier.Verify(input, signature), Is.True);
                }
            }
        }
    }
}