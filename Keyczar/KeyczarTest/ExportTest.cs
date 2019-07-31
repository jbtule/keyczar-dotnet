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
    public class ExportTest : AssertionHelper
    {
        private static readonly String TEST_DATA = Path.Combine("remote-testdata", "existing-data", "dotnet");

        [Test]
        public void TestSymetricKeyExport()
        {
            var ks = new FileSystemKeySet(Util.TestDataPath(TEST_DATA, "aes"));
            Expect(() => ks.ExportPrimaryAsPkcs(Path.Combine(Path.GetTempPath(), "dummy.pem"), () => "dummy"),
                   Throws.InstanceOf<InvalidKeyTypeException>());
        }

        [Test]
        public void TestPublicKeyExport()
        {
            var ks = new FileSystemKeySet(Util.TestDataPath(TEST_DATA, "rsa.public"));
            var path = Path.Combine(Path.GetTempPath(), "dummy.pem");
            Console.WriteLine(path);
            ks.ExportPrimaryAsPkcs(path, () => "dummy");
            var contents = File.ReadAllText(path);
            Expect(contents, Does.Contain("END PUBLIC KEY"));
        }
        
        [Test]
        public void TestPrivateKeyExport()
        {
            var ks = new FileSystemKeySet(Util.TestDataPath(TEST_DATA, "rsa"));
            var path = Path.Combine(Path.GetTempPath(), "dummy-private-withpass.pem");
            Console.WriteLine(path);
            ks.ExportPrimaryAsPkcs(path, () => "dummy");
            var contents = File.ReadAllText(path);
            Expect(contents, Does.Contain("END ENCRYPTED PRIVATE KEY"));
        }
        
        [Test]
        public void TestPriveKeyNoPassExport()
        {
            var ks = new FileSystemKeySet(Util.TestDataPath(TEST_DATA, "rsa"));
            var path = Path.Combine(Path.GetTempPath(), "dummy-private-nopass.pem");
            Console.WriteLine(path);
            ks.ExportPrimaryAsPkcs(path, null);
            var contents = File.ReadAllText(path);
            Expect(contents, Does.Contain("END PUBLIC KEY"));
            Expect(contents, Does.Contain("END RSA PRIVATE KEY"));
        }
    }
}