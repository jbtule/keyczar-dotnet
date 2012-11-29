using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Unofficial;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture]
    public class ExportTest:AssertionHelper
    {
        private static readonly String TEST_DATA = "testdata";

        [Test]
        public void TestSymetricKeyExport()
        {
            var ks = new KeySet(Util.TestDataPath(TEST_DATA, "aes"));
            Expect(() => ks.ExportPrimaryAsPkcs(Path.Combine(Path.GetTempPath(),"dummy.pem"), ()=>"dummy"),Throws.InstanceOf<InvalidKeyTypeException>());
            

        }
    }
}
