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

		[Test]
		public void TestImportPublic(){
			string result;
			var path = Util.TestDataPath(TEST_DATA,"import");
			
			if(Directory.Exists(path))
				Directory.Delete(path,true);
			
			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");
			Expect(result, Is.StringContaining("Created Key set."));

			result = Util.KeyczarTool("pass", 
			                          importkey: null,
			                          location: path,
			                          status: "primary", 
			                          importlocation:Path.Combine(CERTIFICATE_DATA,"rsa-crypt-pkcs8.pem"));
			
			Expect(result, Is.StringContaining("Imported new key version:1"));


			Directory.Delete(path,true);
		}

		[Test]
		public void TestImportPrivate(){
			string result;
			var path = Util.TestDataPath(TEST_DATA,"import");
			
			if(Directory.Exists(path))
				Directory.Delete(path,true);
			
			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");
			Expect(result, Is.StringContaining("Created Key set."));
			
			result = Util.KeyczarTool("pass", 
			                          importkey: null,
			                          location: path,
			                          status: "primary", 
			                          importlocation:Path.Combine(CERTIFICATE_DATA,"rsa-crypt-pkcs8.pem"));
			
			Expect(result, Is.StringContaining("Imported new key version:1"));
			
			
			
			Directory.Delete(path,true);
		}
		
		[Test]
		public void TestPromote(){
			string result;
			
			var path = Util.TestDataPath(TEST_DATA,"promote");
			
			if(Directory.Exists(path))
				Directory.Delete(path,true);
			
			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");
			
			Expect(result, Is.StringContaining("Created Key set."));
			
			result = Util.KeyczarTool(addkey: null, location: path, status: "active");
			
			Expect(result, Is.StringContaining("Created new key version:1"));
			
			
			result = Util.KeyczarTool(promote: null, location: path, version:1);
			Expect(result, Is.StringContaining("PRIMARY"));
			
			Directory.Delete(path,true);
			
		}

		[Test]
		public void TestDemoteRevoke(){
			string result;

			var path = Util.TestDataPath(TEST_DATA,"demote");

			if(Directory.Exists(path))
				Directory.Delete(path,true);

			result =  Util.KeyczarTool(create: null, location: path, purpose: "crypt");
			
			Expect(result, Is.StringContaining("Created Key set."));
			
			result = Util.KeyczarTool(addkey: null, location: path, status: "primary");

			Expect(result, Is.StringContaining("Created new key version:1"));


			result = Util.KeyczarTool(demote: null, location: path, version:1);
			Expect(result, Is.StringContaining("ACTIVE"));

			result = Util.KeyczarTool(demote: null, location: path, version:1);
			Expect(result, Is.StringContaining("INACTIVE"));

			result = Util.KeyczarTool(revoke: null, location: path, version:1);
			Expect(result, Is.StringContaining("Revoked Version 1"));

			var ks = new KeySet(path);
			Expect(ks.Metadata.Versions.Any(),Is.False);

			Directory.Delete(path,true);

		}

	}
}

