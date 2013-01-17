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
using System.IO;
using Keyczar;
using System.Linq;

namespace KeyczarTest.Interop
{
	[TestFixture]
	public abstract class PublicVerifierInterop:VerifierInterop
	{
		public PublicVerifierInterop (string imp):base(imp)
		{
		}

		[Test]
		public void PublicVerify(){
			var subPath = TestData(Location);
			
			using (var publicVerifier = new Verifier(subPath + ".public"))
			{
				var activeSignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "1.out")).First();
				var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(subPath, "2.out")).First();

				Expect(publicVerifier.Verify(Input, activeSignature), Is.True);
				Expect(publicVerifier.Verify(Input, primarySignature), Is.True);
			}
		}
	}
}

