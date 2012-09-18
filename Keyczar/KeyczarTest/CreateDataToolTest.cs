/*  Copyright 2012 James Tuley (jay+code@tuley.name)
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


using System;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Threading;
using NUnit.Framework;


namespace KeyczarTest
{
    [TestFixture]
    public class CreateDataToolTest : AssertionHelper
    {
        private static string WRITE_DATA = "tool_cstestdata";

        private static String input = "This is some test data";
        [TestCase(false, "aes", "")]
        [TestCase(true, "aes_aead", "unofficial", Category = "Unofficial")]
        public void CreateSymmetricAndCrypted(bool unofficial, string topDir, string subDir)
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, topDir, subDir);

            if(Directory.Exists(path))
                Directory.Delete(path,recursive:true);

            result = !unofficial
                ? Util.KeyczarTool(create: null, location: path, purpose: "crypt")
                : Util.KeyczarTool(create: null, location: path, purpose: "crypt", unofficial: null);

            Expect(result, Is.StringContaining("Created Key set."));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining("Created new key version:1"));
            var outPath = Path.Combine(path, "1.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath);


            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining("Created new key version:2"));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath);


            /*Encrypted Keysets*/
            var crypterpath = path;
            path = Util.TestDataPath(WRITE_DATA, topDir+"-crypted", subDir);

            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);

            result = !unofficial
                ? Util.KeyczarTool(create: null, location: path, purpose: "crypt")
             : Util.KeyczarTool(create: null, location: path, purpose: "crypt", unofficial: null);

            Expect(result, Is.StringContaining("Created Key set."));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", crypter: crypterpath);

            Expect(result, Is.StringContaining("Created new key version:1"));
            outPath = Path.Combine(path, "1.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath, crypter: crypterpath);


            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", crypter: crypterpath);

            Expect(result, Is.StringContaining("Created new key version:2"));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath, crypter: crypterpath);
        }

        [TestCase("aes-noprimary")]
		public void CreateNoPrimary(string topDir)
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, topDir);
            if(Directory.Exists(path))
                Directory.Delete(path, recursive:true);
            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");

            Expect(result, Is.StringContaining("Created Key set."));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining("Created new key version:1"));
            var outPath = Path.Combine(path, "1.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath);

            result = Util.KeyczarTool(demote: null, location: path, version: 1);
            Expect(result, Is.StringContaining("Demoted Version 1 to ACTIVE"));
        }


        [TestCase(null,  "hmac", "sign")]
        [TestCase("dsa", "dsa", "sign")]
        [TestCase("rsa", "rsa-sign", "sign")]
        [TestCase("rsa", "rsa", "crypt")]
        public void CreateUseAndPublic(string asymmetric, string topDir, string purpose)
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, topDir);

            if(Directory.Exists(path))
                Directory.Delete(path,recursive:true);

            result = String.IsNullOrWhiteSpace(asymmetric)
                 ? Util.KeyczarTool(create: null, location: path, purpose: purpose)
                 : Util.KeyczarTool(create: null, location: path, purpose: purpose, asymmetric: asymmetric);

            Expect(result, Is.StringContaining("Created Key set."));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining("Created new key version:1"));
            var outPath = Path.Combine(path, "1.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath);


            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining("Created new key version:2"));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, message: input, destination: outPath);

  
            if (!string.IsNullOrWhiteSpace(asymmetric))
            {
                var pubpath = Util.TestDataPath(WRITE_DATA, topDir + ".public");
                if(Directory.Exists(pubpath))
				    Directory.Delete(pubpath,true);
                result = Util.KeyczarTool(pubKey: null, location: path, destination: pubpath);
                Expect(result, Is.StringContaining("Created new public keyset"));
            }
        }


        [TestCase("dsa", "dsa-sign", "sign")]
        [TestCase("rsa", "rsa-sign", "sign")]
        [TestCase("rsa", "rsa-crypt", "crypt")]
        public void CreateAndExport(string asymmetric, string topDir, string purpose)
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, topDir,"certificates");
            
            if(Directory.Exists(path))
                Directory.Delete(path,recursive:true);

            result = String.IsNullOrWhiteSpace(asymmetric)
                 ? Util.KeyczarTool(create: null, location: path, purpose: purpose)
                 : Util.KeyczarTool(create: null, location: path, purpose: purpose, asymmetric: asymmetric);

            Expect(result, Is.StringContaining("Created Key set."));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining("Created new key version:1"));
           
            
            var exportpath = Util.TestDataPath(WRITE_DATA, topDir + "-pkcs8.pem", "certificates");
            //send password via std in
            result = Util.KeyczarTool("pass", "pass", export: null, location: path, destination: exportpath);

            Expect(result, Is.StringContaining("Exported to pem."));

            if (!string.IsNullOrWhiteSpace(asymmetric))
            {
                var pubpath = Util.TestDataPath(WRITE_DATA, topDir + ".public", "certificates");
                if(Directory.Exists(pubpath))
				    Directory.Delete(pubpath,true);
                result = Util.KeyczarTool(pubKey: null, location: path, destination: pubpath);
                Expect(result, Is.StringContaining("Created new public keyset"));
            }
        }

        [Test]
        public void CreatePbeKeySet()
        {
            string result,outPath;

            var path = Util.TestDataPath(WRITE_DATA, "pbe_json");

            if(Directory.Exists(path))
			    Directory.Delete(path, true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");

            Expect(result, Is.StringContaining("Created Key set."));

            //First time double prompts for password
            result = Util.KeyczarTool("cartman", "cartman", addkey: null, location: path, status: "primary", password: null);

            Expect(result, Is.StringContaining("Created new key version:1"));
            outPath = Path.Combine(path, "1.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool("cartman", usekey: null, location: path, message: input, destination: outPath, password: null);


            result = Util.KeyczarTool("cartman", addkey: null, location: path, status: "primary", password: null);

            Expect(result, Is.StringContaining("Created new key version:2"));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath);//Delete if already exists
            Util.KeyczarTool("cartman",  usekey: null, location: path, message: input, destination: outPath, password: null);

        }


      
    }
}