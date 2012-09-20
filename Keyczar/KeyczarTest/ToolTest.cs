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
 * 
 * 
 * 8/2012 directly ported to c# - jay+code@tuley.name (James Tuley)
 * 
 */


using System;
using System.Globalization;
using System.IO;
using System.Linq;
using NUnit.Framework;
using Keyczar;

namespace KeyczarTest
{
	[TestFixture]
	public class ToolTest:AssertionHelper
	{

		private String TEST_DATA = Path.GetTempPath();
		private string CERTIFICATE_DATA= Path.Combine("testdata","certificates");

        private static String input = "This is some test data";
        private static byte[] bigInput = new byte[10000];


        [TestCase("zlib")]
        [TestCase("gzip")]
        public void TestEncryptCompression(string compress)
        {
            string result;
            var subPath = Util.TestDataPath(TEST_DATA, "compress");

            if (Directory.Exists(subPath))
                Directory.Delete(subPath, true);

            result = Util.KeyczarTool(create: null, location: subPath, purpose: "crypt");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));


            result = Util.KeyczarTool(addkey: null, location: subPath, status: "primary");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));


            var ptext = Path.Combine(subPath, "ptext");
            File.WriteAllBytes(ptext, bigInput);


            var ctext = Path.Combine(subPath, "ctext");

            result = Util.KeyczarTool(
                                  usekey: null,
                                  location: subPath,
                                  message: ptext,
                                  file:null,
                                  destination: ctext,
                                  compression: compress,
                                  binary:null
                                  );


            var compression = compress == "zlib" ? CompressionType.Zlib : CompressionType.Gzip;
   

            using (var crypter = new Crypter(subPath) { Compression = compression })
            {
                using (var write  = new MemoryStream())
                using (var read = File.OpenRead(ctext))
                {
                    
                    crypter.Decrypt(read, write);
                    Expect(write.ToArray(),Is.EqualTo(bigInput));
                }

                Expect(new FileInfo(ctext).Length,Is.LessThan(new FileInfo(ptext).Length));

            }
        }

	    [Test]
		public void TestImportPublic(){
			string result;
			var path = Util.TestDataPath(TEST_DATA,"import");
			
			if(Directory.Exists(path))
				Directory.Delete(path,true);
			
			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

			result = Util.KeyczarTool("pass", 
			                          importkey: null,
			                          location: path,
			                          status: "primary", 
			                          importlocation:Path.Combine(CERTIFICATE_DATA,"rsa-crypt-pkcs8.pem"));
			
			Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgImportedNewKey));


			Directory.Delete(path,true);
		}

		[Test]
		public void TestImportPrivate(){
			string result;
			var path = Util.TestDataPath(TEST_DATA,"import");
			
			if(Directory.Exists(path))
				Directory.Delete(path,true);
			
			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt", asymmetric:"rsa");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));
			
			result = Util.KeyczarTool("pass", 
			                          importkey: null,
			                          location: path,
			                          status: "primary", 
			                          importlocation:Path.Combine(CERTIFICATE_DATA,"rsa-crypt-pkcs8.pem"));

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgImportedNewKey));
			
			
			
			Directory.Delete(path,true);
		}


        [Test]
        public void TestOperateOnCryptedKeys()
        {
            string result;
            var path = Util.TestDataPath(TEST_DATA, "crypting");

            var pathc = Util.TestDataPath(TEST_DATA, "rsa-crypted");

            if (Directory.Exists(path))
                Directory.Delete(path, true);

            if (Directory.Exists(pathc))
                Directory.Delete(pathc, true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            result = Util.KeyczarTool(create: null, location: pathc, purpose: "crypt", asymmetric:null);
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: pathc,crypter:path, status: "primary");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            var pathi= Path.Combine(pathc,"out.pem");

            result = Util.KeyczarTool(
                                   "pass",
                                   "pass",
                                   export: null,
                                   location: pathc,
                                   crypter: path,
                                   destination: pathi);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgExportedPem));
            
            result = Util.KeyczarTool("pass",
                                  importkey: null,
                                  location: pathc, 
                                  status: "primary", 
                                  crypter: path,
                                  importlocation: pathi);
        
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgImportedNewKey));
              
     
            var pathp= Path.Combine(pathc, "export");

            result = Util.KeyczarTool(
                                  pubkey: null,
                                  location: pathc,
                                  crypter: path,
                                  destination: pathp
                                  );
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));

            var patho = Path.Combine(pathc, "1.out");

            result = Util.KeyczarTool(
                                  usekey: null,
                                  location: pathc,
                                  crypter: path,
                                  message: input,
                                  destination: patho
                                  );


            using (var kcrypter = new Crypter(path))
            {
                var eks = new EncryptedKeySet(pathc, kcrypter);
                Expect(eks.Metadata.Encrypted, Is.True);
                using (var crypter = new Crypter(eks))
                {
                    result = crypter.Decrypt(File.ReadAllText(patho));
                    Expect(result, Is.EqualTo(input));
                }
            }

            Directory.Delete(path, true);
        }

        [Test]
        public void TestOperateOnPbeCryptKeys()
        {
            string result;
            
            
            var path = Util.TestDataPath(TEST_DATA, "rsa-pbe2");
            var pathc = Util.TestDataPath(TEST_DATA, "rsa-crypted2");

            if (Directory.Exists(path))
                Directory.Delete(path, true);
            if (Directory.Exists(pathc))
                Directory.Delete(pathc, true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt", unofficial:null);
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool("cartman", "cartman", addkey: null, location: path, password: null, status: "primary");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            result = Util.KeyczarTool(create: null, location: pathc, purpose: "crypt", asymmetric: null);
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool("cartman", addkey: null, location: pathc, crypter: path, password: null, status: "primary");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            var pathi = Path.Combine(pathc, "out.pem");

            result = Util.KeyczarTool(
                                   "cartman",
                                   "pass",
                                   "pass",
                                   export: null,
                                   location: pathc,
                                   password: null,
                                   crypter: path,
                                   destination: pathi);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgExportedPem));

            result = Util.KeyczarTool("cartman", "pass",
                                  importkey: null,
                                  location: pathc,
                                  status: "primary", 
                                  crypter: path,
                                  password: null,
                                  importlocation: pathi);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgImportedNewKey));




            var pathp = Path.Combine(pathc, "export");

            result = Util.KeyczarTool(
                                "cartman",
                                  pubkey: null,
                                  location: pathc,
                                  crypter: path, 
                                  password: null,
                                  destination: pathp
                                  );
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));

            var patho = Path.Combine(pathc, "1.out");

            result = Util.KeyczarTool(
                                 "cartman",
                                  usekey: null,
                                  location: pathc,
                                  crypter: path,
                                  password: null,
                                  message: input,
                                  destination: patho
                                  );

            using(var pks =new PbeKeySet(path, () => "cartman"/*hardcoding because this is a test*/))
            using (var kcrypter = new Crypter(pks))
            {
                var eks = new EncryptedKeySet(pathc, kcrypter);
                using (var crypter = new Crypter(eks))
                {
                    Expect(pks.Metadata.Encrypted, Is.True);
                    Expect(eks.Metadata.Encrypted,Is.True);
                    result = crypter.Decrypt(File.ReadAllText(patho));
                    Expect(result, Is.EqualTo(input));
                }

            }
            Directory.Delete(pathc, true);

        }

        [Test]
        public void TestOperateOnPbeKeys()
        {
            string result;

            var pathc = Util.TestDataPath(TEST_DATA, "rsa-pbe");

            if (Directory.Exists(pathc))
                Directory.Delete(pathc, true);

            result = Util.KeyczarTool(create: null, location: pathc, purpose: "crypt", asymmetric: null);
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool("cartman", "cartman", addkey: null, location: pathc, password: null, status: "primary");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            var pathi = Path.Combine(pathc, "out.pem");

            result = Util.KeyczarTool(
                                   "cartman",
                                   "pass",
                                   "pass",
                                   export: null,
                                   location: pathc,
                                   password: null,
                                   destination: pathi);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgExportedPem));

            result = Util.KeyczarTool("cartman", "pass",
                                  importkey: null,
                                  location: pathc,
                                  status: "primary",
                                  password: null,
                                  importlocation: pathi);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgImportedNewKey));


            var pathp = Path.Combine(pathc, "export");

            result = Util.KeyczarTool(
                     "cartman",
                      pubkey: null,
                      location: pathc,
                      password: null,
                      destination: pathp
                      );
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));

            var patho = Path.Combine(pathc, "1.out");

            result = Util.KeyczarTool(
                                 "cartman", 
                                  usekey: null,
                                  location: pathc,
                                  password: null,
                                  message: input,
                                  destination: patho
                                  );
            using(var pks =new PbeKeySet(pathc, ()=>"cartman"/*hardcoding because this is a test*/))
            using (var crypter = new Crypter(pks))
            {
                Expect(pks.Metadata.Encrypted, Is.True);
                result = crypter.Decrypt(File.ReadAllText(patho));
                Expect(result, Is.EqualTo(input));
            }

            Directory.Delete(pathc, true);
        }

		[Test]
		public void TestPromote(){
			string result;
			
			var path = Util.TestDataPath(TEST_DATA,"promote");
			
			if(Directory.Exists(path))
				Directory.Delete(path,true);
			
			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));
			
			result = Util.KeyczarTool(addkey: null, location: path, status: "active");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));
			
			
			result = Util.KeyczarTool(promote: null, location: path, version:1);
			Expect(result, Is.StringContaining("PRIMARY"));
			
			Directory.Delete(path,true);
			
		}

        [Test]
        public void TestInvalid()
        {
            string result;

            var path = Util.TestDataPath(TEST_DATA, "invalid");

            if (Directory.Exists(path))
                Directory.Delete(path, true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "blah");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgInvalidStatus));

            result = Util.KeyczarTool(demote: null, location: path, version: "1");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgUnknownVersion));
            
            result = Util.KeyczarTool(promote: null, location: path, version: "1");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgUnknownVersion));

            result = Util.KeyczarTool(revoke: null, location: path, version: "1");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCouldNotRevoke));

            //Don't overwrite
            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgExistingKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            result = Util.KeyczarTool(demote: null, location: path, version: "1");
            Expect(result, Is.StringContaining("ACTIVE"));

            result = Util.KeyczarTool(demote: null, location: path, version: "1");
            Expect(result, Is.StringContaining("INACTIVE"));

            Directory.CreateDirectory(Path.Combine(path, "2.temp"));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCouldNotWrite));

            Directory.CreateDirectory(Path.Combine(path, "meta.temp"));

            result = Util.KeyczarTool(demote: null, location: path, version: "1");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCouldNotWrite));

            result = Util.KeyczarTool(promote: null, location: path, version: "1");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCouldNotWrite));

            result = Util.KeyczarTool(revoke: null, location: path, version: "1");
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCouldNotWrite));


            Directory.Delete(path, true);

        }

        [Test]
        public void TestAddPadding()
        {
            string result;

            var path = Util.TestDataPath(TEST_DATA, "padding");
            var path2 = Util.TestDataPath(TEST_DATA, "padding.public");

            if (Directory.Exists(path))
                Directory.Delete(path, true);
            if (Directory.Exists(path2))
                Directory.Delete(path2, true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt", asymmetric:null);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", padding:"PKCS",size:"1024");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));


            var ks = new KeySet(path);
            dynamic key = ks.GetKey(1);
            Expect((int)key.Size, Is.EqualTo(1024));
            Expect((string)key.Padding, Is.EqualTo("PKCS"));



            result = Util.KeyczarTool(pubkey: null, location: path, destination: path2);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));

            var ks2 = new KeySet(path);
            dynamic key2 = ks2.GetKey(1);
            Expect(key2.Size, Is.EqualTo(1024));
            Expect(key2.Padding, Is.EqualTo("PKCS"));

            Directory.Delete(path2, true);
            Directory.Delete(path, true);

        }

		[Test]
		public void TestDemoteRevoke(){
			string result;

			var path = Util.TestDataPath(TEST_DATA,"demote");

			if(Directory.Exists(path))
				Directory.Delete(path,true);

			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));
			
			result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));


			result = Util.KeyczarTool(demote: null, location: path, version:1);
			Expect(result, Is.StringContaining("ACTIVE"));

			result = Util.KeyczarTool(demote: null, location: path, version:1);
			Expect(result, Is.StringContaining("INACTIVE"));

			result = Util.KeyczarTool(revoke: null, location: path, version:1);
			Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgRevokedVersion));

			var ks = new KeySet(path);
			Expect(ks.Metadata.Versions.Any(),Is.False);

			Directory.Delete(path,true);

		}

	}
}

