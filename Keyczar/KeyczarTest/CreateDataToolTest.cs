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
using Keyczar;
using NUnit.Framework;


namespace KeyczarTest
{
    [TestFixture, Category("Create")]
    public class CreateDataToolTest : AssertionHelper
    {
        private static string WRITE_DATA = Path.Combine("gen-testdata", "tool_cstestdata");

        private static String input = "This is some test data";

        [TestCase(null, "hmac", "sign", "")]
        [TestCase(false, "aes", "crypt", "")]
        [TestCase(true, "aes_aead", "crypt", "unofficial", Category = "Unofficial")]
        public void CreateSymmetricAndUse(bool unofficial, string topDir, string purpose, string subDir)
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, topDir, subDir);

            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");
            var type = !unofficial
                           ? "AES_HMAC_SHA1"
                           : "AES_GCM";

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", type:type);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));
            var outPath = Path.Combine(path, "1.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, destination: outPath, additionalArgs: new[] {input});


            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", type:type);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, destination: outPath, additionalArgs: new[] {input});

            if (purpose == "crypt")
            {
                /*Encrypted Keysets*/
                var crypterpath = path;
                path = Util.TestDataPath(WRITE_DATA, topDir + "-crypted", subDir);

                if (Directory.Exists(path))
                    Directory.Delete(path, recursive: true);

            result = Util.KeyczarTool(create: null, location: path, purpose: "crypt");
             
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", crypter: crypterpath, type:type);

                Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));
                outPath = Path.Combine(path, "1.out");
                File.Delete(outPath); //Delete if already exists
                Util.KeyczarTool(usekey: null, location: path, destination: outPath, crypter: crypterpath,
                                 additionalArgs: new[] {input});



            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", crypter: crypterpath, type:type);


                Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

                outPath = Path.Combine(path, "2.out");
                File.Delete(outPath); //Delete if already exists
                Util.KeyczarTool(usekey: null, location: path, destination: outPath, crypter: crypterpath,
                                 additionalArgs: new[] {input});
            }
        }

        [TestCase("aes-noprimary")]
        public void CreateNoPrimary(string topDir)
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, topDir);
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
            result = Util.KeyczarTool(create: null, name: "Test", location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));
            var outPath = Path.Combine(path, "1.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, destination: outPath, additionalArgs: new[] {input});

            result = Util.KeyczarTool(demote: null, location: path, version: 1);
            Expect(result,
                   Is.StringContaining(String.Format(KeyczarTool.Localized.MsgDemotedVersion, 1, KeyStatus.Active)));
        }


        [TestCase("dsa_priv", "dsa", "dsa", "sign")]
        [TestCase("rsa_priv", "rsa", "rsa-sign", "sign")]
        [TestCase("rsa_priv", "rsa", "rsa", "crypt")]
        [TestCase("c#_rsa_sign_priv", "rsa", "rsa-sign", "sign")]
        public void CreateUseAndPublic(string type, string algId, string topDir, string purpose)
        {
            string result;
            string subDir = "";
            KeyType keyType = type;

            bool unofficial = keyType.Unofficial;

            if (unofficial)
            {
                subDir = "unofficial";
            }
            var path = Util.TestDataPath(WRITE_DATA, topDir);

            if (Directory.Exists(path))
                Directory.Delete(path,recursive:true);

            result = Util.KeyczarTool(create: null, name: "Test", location: path, purpose: purpose);


            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", type: keyType);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));
            var outPath = Path.Combine(path, "1.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, destination: outPath, additionalArgs: new[] {input});


            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", type: keyType);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool(usekey: null, location: path, destination: outPath, additionalArgs: new[] {input});


            var pubpath = Util.TestDataPath(WRITE_DATA, topDir + ".public", subDir);
            if (Directory.Exists(pubpath))
                Directory.Delete(pubpath, true);
            result = Util.KeyczarTool(pubkey: null, location: path, destination: pubpath);
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));
        }

        [TestCase("dsa_priv", "dsa", "dsa", "sign")]
        [TestCase("rsa_priv", "rsa", "rsa-sign", "sign")]
        [TestCase("rsa_priv", "rsa", "rsa", "crypt")]
        [TestCase("c#_rsa_sign_priv", "rsa", "rsa-sign", "sign")]
        public void CreateUseAndPublicSized(string type, string algId, string topDir, string purpose)
        {
            KeyType keyType = type;

            bool unofficial = keyType.Unofficial;

            topDir += "-sizes";

            string result;
            string subDir = "";
            if (unofficial)
                subDir = "unofficial";

            var path = Util.TestDataPath(WRITE_DATA, topDir, subDir);

            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);

            result = !unofficial
                         ? Util.KeyczarTool(create: null, name: "Test", location: path, purpose: purpose,
                                            asymmetric: algId)
                         : Util.KeyczarTool(create: null, name: "Test", location: path, purpose: purpose,
                                            asymmetric: algId, unofficial: null);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));


            foreach (var size in keyType.KeySizeOptions)
            {
                result = Util.KeyczarTool(addkey: null, location: path, status: "primary", size: size);

                Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));
                var outPath = Path.Combine(path, String.Format("{0}.out", size));
                File.Delete(outPath); //Delete if already exists
                Util.KeyczarTool(usekey: null, location: path, destination: outPath, additionalArgs: new[] {input});
            }

            var pubpath = Util.TestDataPath(WRITE_DATA, topDir + ".public", subDir);
            if (Directory.Exists(pubpath))
                Directory.Delete(pubpath, true);
            result = Util.KeyczarTool(pubkey: null, location: path, destination: pubpath);
            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));
        }

        [TestCase("dsa", "dsa-sign", "sign", false)]
        [TestCase("rsa", "rsa-sign", "sign", false)]
        [TestCase("rsa", "rsa-crypt", "crypt", false)]
        [TestCase("rsa", "rsa-sign-unofficial", "sign", true)]
        public void CreateAndExport(string asymmetric, string topDir, string purpose, bool unofficial)
        {
            string result;

            string type;
            if (String.IsNullOrWhiteSpace(asymmetric))
            {
                type = "HMAC_SHA1";
            }
            else if (asymmetric == "rsa")
            {
                type = "RSA_SHA1";
            }
            else
            {
                type = "DSA_SHA1";
            }

            var path = Util.TestDataPath(WRITE_DATA, topDir,"certificates");
            
            if(Directory.Exists(path))
                Directory.Delete(path,recursive:true);


            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);

            result = !unofficial
                         ? Util.KeyczarTool(create: null, name: "Test", location: path, purpose: purpose,
                                            asymmetric: asymmetric)
                         : Util.KeyczarTool(create: null, name: "Test", location: path, purpose: purpose,
                                            asymmetric: asymmetric, unofficial: null);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary", type: type);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));


            var exportpath = Util.TestDataPath(WRITE_DATA, topDir + "-pkcs8.pem", "certificates");
            //send password via std in
            result = Util.KeyczarTool("pass", "pass", export: null, location: path, destination: exportpath);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgExportedPem));

            if (!string.IsNullOrWhiteSpace(asymmetric))
            {
                var exportpubpath = Util.TestDataPath(WRITE_DATA, topDir + "-public.pem", "certificates");
                var pubpath = Util.TestDataPath(WRITE_DATA, topDir + ".public", "certificates");
                if (Directory.Exists(pubpath))
                    Directory.Delete(pubpath, true);
                result = Util.KeyczarTool(pubKey: null, location: path, destination: pubpath);
                Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgNewPublicKeySet));
                result = Util.KeyczarTool(export: null, location: pubpath, destination: exportpubpath);
                Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgExportedPem));
            }
        }

        [Test]
        public void CreatePbeKeySet()
        {
            string result, outPath;

            var path = Util.TestDataPath(WRITE_DATA, "pbe_json");

            if (Directory.Exists(path))
                Directory.Delete(path, true);

            result = Util.KeyczarTool(create: null, name: "Test", location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            //First time double prompts for password
            result = Util.KeyczarTool("cartman", "cartman", addkey: null, location: path, status: "primary",
                                      password: null);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            outPath = Path.Combine(path, "1.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool("cartman", usekey: null, location: path, destination: outPath, password: null,
                             additionalArgs: new[] {input});


            result = Util.KeyczarTool("cartman", addkey: null, location: path, status: "primary", password: null);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            outPath = Path.Combine(path, "2.out");
            File.Delete(outPath); //Delete if already exists
            Util.KeyczarTool("cartman", usekey: null, location: path, destination: outPath, password: null,
                             additionalArgs: new[] {input});
        }

        [Test]
        public void CreateAndModifyPbeKeySet()
        {
            string result;

            var path = Util.TestDataPath(WRITE_DATA, "pbe_scratch");

            if (Directory.Exists(path))
                Directory.Delete(path, true);

            result = Util.KeyczarTool(create: null, name: "Test", location: path, purpose: "crypt");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKeySet));

            result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgCreatedKey));

            result = Util.KeyczarTool("passwordo", "passwordo", password: null, location: path);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgAddedPasssword));

            result = Util.KeyczarTool("passwordo", "changed", "changed", password: null, location: path);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgChangedPassword));

            result = Util.KeyczarTool("changed", password: null, location: path, remove: null);

            Expect(result, Is.StringContaining(KeyczarTool.Localized.MsgRemovedPassword));
        }
    }
}