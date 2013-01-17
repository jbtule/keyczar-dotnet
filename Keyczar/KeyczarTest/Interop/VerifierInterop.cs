//
//  Copyright 2013  
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
using System;
using NUnit.Framework;
using Keyczar;
using System.IO;
using System.Linq;

namespace KeyczarTest.Interop
{
	public abstract class VerifierInterop:Interop
	{
		protected string Location;

		protected static String Input = "This is some test data";


		public VerifierInterop (string imp):base(imp)
		{
		}

		[Test]
		public void Verify(){

			var path = TestData(Location);
			using (var verifier = new Verifier(path))
			{
				var activeSignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "1.out")).First();
				var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.out")).First();
				Expect(verifier.Verify(Input, activeSignature), Is.True);
				Expect(verifier.Verify(Input, primarySignature), Is.True);
			}
		}
	}
}

