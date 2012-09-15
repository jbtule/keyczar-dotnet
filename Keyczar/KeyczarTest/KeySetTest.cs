
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
          public void TestGetPrimaryFails()
          {
              var reader = new KeySet(Util.TestDataPath(TEST_DATA, "aes-noprimary"));
              Expect(() => new GetPrimary(reader).GetPrimaryExposed(), Throws.TypeOf<MissingPrimaryKeyException>());

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
