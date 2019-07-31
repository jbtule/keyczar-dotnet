using NUnit.Framework;
using System;
using System.IO;
using System.Linq;

using Keyczar;
namespace KeyczarTest
{
    [TestFixture()]
    public class DsaJavaJunkTest: BaseHelper
    {

		public String Input
		{
			get { return "This is some test data"; }
		}


		public string TestData(string dir)
		{
			return Util.TestDataPath(Path.Combine("remote-testdata", "special-case" ), dir);
		}



		[Test]
		public void VerifyAttached()
		{
			var path = TestData("java-junk-dsa");
			using (var verifier = new AttachedVerifier(path))
			{
				var primarySignature = (WebBase64)File.ReadAllLines(Path.Combine(path, "2.attached")).First();

				Expect(verifier.Verify(primarySignature), Is.True);
			}
		}

		[Test]
		public void VerifyAttachedStrictFail()
		{
			var path = TestData("java-junk-dsa");
			using (var verifier = new AttachedVerifier(path))
			{
                verifier.Config.StrictDsaVerification = true;
				var primarySignature = (WebBase64)File.ReadAllLines(Path.Combine(path, "2.attached")).First();

                Expect(verifier.Verify(primarySignature), Is.False);
			}
		}


	}
}
