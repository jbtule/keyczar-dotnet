
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


using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using NUnit.Framework;
using Newtonsoft.Json.Linq;

namespace KeyczarTest
{
    [TestFixture("testdata")]
    [TestFixture("cstestdata")]
    [TestFixture("tool_cstestdata")]
    public class KeySetTest:AssertionHelper
    {

          private readonly String TEST_DATA;

          public KeySetTest(string testPath)
          {
              TEST_DATA = testPath;
          }

          [Test]
          public void TestGetPrimary(){
                // based on the checked in files, we know version 2 is primary.
              var reader = new KeySet(Util.TestDataPath(TEST_DATA, "rsa"));
                var knownPrimaryKey = reader.GetKey(2 /* primary key version */);
                var readerKey = new GetPrimary(reader).GetPrimaryExposed();
                Expect(readerKey.GetKeyHash(), Is.EqualTo(knownPrimaryKey.GetKeyHash()));
          }

           [Test]
           public void TestEncryptedKeysetForNonEncryptedData()
           {
               var nonencryptedpath = Util.TestDataPath(TEST_DATA, "rsa");
               using (var pbereader = new PbeKeySet(nonencryptedpath,()=>"dummy"))
               {
                        var key = pbereader.GetKey(1);
                        Expect(key, Is.Not.Null);
               }

    
               using (var crypter = new Crypter(nonencryptedpath))
               {
                   var encreader = new EncryptedKeySet(nonencryptedpath, crypter);
                   var key = encreader.GetKey(1);
                   Expect(key, Is.Not.Null);
               }

              
           }

          [Test]
          public void TestPbeKeysetRead(){
              Func<string> password = ()=>"cartman"; //Hardcoded because this is a test
              using (var reader = new PbeKeySet(new KeySet(Util.TestDataPath(TEST_DATA, "pbe_json")), password))
              {

				Expect(reader.Metadata.Encrypted, Is.True);

                  var data1 = Encoding.UTF8.GetString(reader.GetKeyData(1));
                  var data2 = Encoding.UTF8.GetString(reader.GetKeyData(1));

                  var token1 = JToken.Parse(data1);

                  var size = token1["size"];
                  Expect(size.ToString(), Is.EqualTo("128"));

                  var token2 = JToken.Parse(data2);
                  var mode = token2["mode"];
                  Expect(mode.ToString(), Is.EqualTo("CBC"));
              }
          }

          [Test]
          public void TestOverwriteFalse()
          {
              using (var ks = new MutableKeySet(new KeyMetadata { Name = "Don't Write", Purpose = KeyPurpose.DECRYPT_AND_ENCRYPT, KeyType = KeyType.AES }))
              {
                  ks.AddKey(KeyStatus.PRIMARY);
                  var writer = new KeySetWriter(Util.TestDataPath(TEST_DATA, "pbe_json"),overwrite:false);
                  
                  Expect(() => ks.Save(writer), Is.False);

              }
          }


		[Test]
		public void TestRevoke()
		{
			using(var reader = new MutableKeySet(Util.TestDataPath(TEST_DATA, "aes-noprimary"))){
				var status =reader.Demote(1);
				Expect(status, Is.EqualTo(KeyStatus.INACTIVE));
				var re = reader.Revoke(1);
				Expect(re,Is.True);
				Expect(reader.Metadata.Versions.Any(),Is.False);
			}
		}

		[Test]
		public void TestPromotePrimary()
		{
			using(var reader = new MutableKeySet(Util.TestDataPath(TEST_DATA, "aes-noprimary"))){
				var status =reader.Promote(1);
				Expect(status, Is.EqualTo(KeyStatus.PRIMARY));
				Expect(() => new GetPrimary(reader).GetPrimaryExposed(), Is.Not.Null);
			}
		}

        [Test]
        public void TestAddUnknownProperty()
        {
            using (var reader = new MutableKeySet(Util.TestDataPath(TEST_DATA, "aes-noprimary")))
            {
              
                Expect(() => reader.AddKey(KeyStatus.PRIMARY,options:new{FakeProp="BlahBlah"}), Throws.Nothing);
            }
        }

          [Test]
          public void TestGetPrimaryFails()
          {
              var reader = new KeySet(Util.TestDataPath(TEST_DATA, "aes-noprimary"));
              Expect(() => new GetPrimary(reader).GetPrimaryExposed(), Throws.TypeOf<MissingPrimaryKeyException>());

          }

          [Test]
          public void TestAddKeySizeFails()
          {
              using (var reader = new MutableKeySet(Util.TestDataPath(TEST_DATA, "aes-noprimary")))
              {
                  Expect(() => reader.AddKey(KeyStatus.PRIMARY, keySize: 16), Throws.TypeOf<InvalidKeyTypeException>());
              }
          }

        protected class GetPrimary:Keyczar.Keyczar
        {
            public GetPrimary(string keySetLocation)
                : base(new KeySet(keySetLocation))
            {
            }

            public GetPrimary(IKeySet keySet) : base(keySet)
            {
            }

            public Key GetPrimaryExposed()
            {
                return GetPrimaryKey();
            }
        }
    }
}
