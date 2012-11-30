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
 * This test case verifies that OAEP and PKCS1 v1.5 padding are both supported for RSA keys.
 *
 * @author swillden@google.com (Shawn Willden)
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Compat;
using NUnit.Framework;

namespace KeyczarTest
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable"), TestFixture]
    public class RsaPaddingTest:AssertionHelper
    {

         private static readonly String input = "testdata";
  private IKeySet defaultReader;
  private IKeySet oaepReader;
  private IKeySet pkcsReader;
  private IKeySet invalidReader;


  private static readonly String pubKeyStringPrefix =
      "{\"modulus\":\"ANRvrByiiuvqU53_8EdhXR_ieDX7gsMpnHTRZn8vuPRlooLcVg_TP_6DrkHDT1kSfso"
          + "OMkpCw6dv7qJEqHS8kO7qUwBh3ZtM02-9jc0VY--Pjp8uFeq6SMkCa8EpzSyBSjucOoUi-yqs0-g"
          + "KGGgd_0N88A37aGNedtCWqyePYsi7\",\"publicExponent\":\"AQAB\",\"size\":1024";
  private static readonly String pubKeyStringSuffix = "}";

  private static readonly String oaepPaddingString = ",\"padding\":\"OAEP\"";
  private static readonly String pkcsPaddingString = ",\"padding\":\"PKCS\"";
  private static readonly String invalidPaddingString = ",\"padding\":\"INVALID\"";

  private static readonly String privKeyStringPrefix = "{\"publicKey\":";
  private static readonly String privKeyStringSuffix =
      ",\"privateExponent\":\"KAq4lVkp-Ffd1P1GDB5VEEp-wCYdOq4gOICz4itboG172VCwxCDcghvN_8V"
          + "Rsodi8LEGV6sH-AqIH3vziLV2V8pXV6E4ZxpmKQVM4vtK0P-cHz3IExXzQaM5q-BrYNuzhl-Qzs9"
          + "lsD5IxNPQYwGgDAL5yl_e1z41VDyfOCqQZIE\",\"primeP\":\"AOlnBr4i8vKddjvRr2upGTcl"
          + "gRxQbqOwvXdcif6hFk_7iBxwAfltDzSlDR1Zx2i2IaSJJOQEilvBPcYx8Lq9_0E\",\"primeQ\""
          + ":\"AOkA_VZjN7PQkJgDxcpvn_ptFCpdKhA0NPBu9PmocaUKmfyF-KQK6bZf5-gOgCvy01KdIx_xy"
          + "DPf8bres9x8hPs\",\"primeExponentP\":\"ANfFINyhnotfui_u1wbmWqM6jrNIQCAfgehYql"
          + "G1RdVHKTtw6MJXahk3BHq_xrMsvMlI58vLzsSoTp1tCaj5gIE\",\"primeExponentQ\":\"ALl"
          + "66jB8pvjjTFdWmXr-xPELKARZSYTAqmvDSAv9hQoGmHInC7k6XrWpPujBslJJ6ONY538kb2SsHrf"
          + "NVIxuK0U\",\"crtCoefficient\":\"AM-mryy-gC1CHOpA-Mtqfe3pM6IIcsQfiLRswtez5mid"
          + "jb4Gy7juZKHIuPz_t7y0s2C4mSXsqwi2W5gj9MqbXUw\",\"size\":1024}";


      private byte[] BuildKey(String paddingString)
      {
          return Encoding.UTF8.GetBytes(privKeyStringPrefix
              + pubKeyStringPrefix
              + paddingString
              + pubKeyStringSuffix
              + privKeyStringSuffix);
      }
          [SetUp]
          public void setUp()
          {

              defaultReader = new ImportedKeySet(Key.Read(KeyType.RsaPriv, BuildKey("")), KeyPurpose.DecryptAndEncrypt);
              oaepReader = new ImportedKeySet(Key.Read(KeyType.RsaPriv, BuildKey(oaepPaddingString)), KeyPurpose.DecryptAndEncrypt);
              pkcsReader = new ImportedKeySet(Key.Read(KeyType.RsaPriv, BuildKey(pkcsPaddingString)), KeyPurpose.DecryptAndEncrypt);
              invalidReader = new ImportedKeySet(Key.Read(KeyType.RsaPriv, BuildKey(invalidPaddingString)), KeyPurpose.DecryptAndEncrypt);
          }

          [Test]
          public void TestPaddingDefault(){
            // First ensure the primary key doesn't contain explicit padding info, in case
            // someone changed the key in the test data.
            var keyData = Encoding.UTF8.GetString(BuildKey(""));
            Expect(keyData.ToLowerInvariant().Contains("padding"),Is.False,"Key should not contain padding field");
          }

           [Test]
          public void TestPkcsEncryption(){
            var ciphertext = new Encrypter(pkcsReader).Encrypt(input);
            var plaintext = new Crypter(pkcsReader).Decrypt(ciphertext);
            Expect(plaintext, Is.EqualTo(input));
          }

         [Test]
          public void TestHashMismatch()
         {
             var oaepPaddingKey = oaepReader.GetKey(1);
             var pkcsPaddingKey = pkcsReader.GetKey(1);

            Expect(oaepPaddingKey.GetKeyHash(), Is.Not.EqualTo(pkcsPaddingKey.GetKeyHash()));
          } 
        
        [Test]
          public void TestIncompatibility() {
            var encrypter = new Encrypter(oaepReader);
            var ciphertext = encrypter.Encrypt(input);
            var crypter = new Crypter(pkcsReader);
            Expect(()=> crypter.Decrypt(ciphertext), Throws.TypeOf<InvalidCryptoDataException>());  
          
          }
    }
}
