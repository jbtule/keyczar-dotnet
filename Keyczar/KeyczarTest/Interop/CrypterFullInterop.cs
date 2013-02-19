using System.IO;
using System.Linq;
using Keyczar;
using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture]
    public abstract class CrypterFullInterop : Interop
    {
        protected string Location;
        protected string SignLocation;

        public CrypterFullInterop(string imp)
            : base(imp)
        {
        }

        [Test]
        public void DecryptSession()
        {
            var path = TestData(Location);

            var material = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.session.material")).First();
            var ciphertext = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.session.ciphertext")).First();

            using (var crypter = new Crypter(path))
            using (var sessionCrypter = new SessionCrypter(crypter, material))
            {
                var decrypted = sessionCrypter.Decrypt(ciphertext);
                Expect(decrypted, Is.EqualTo(Input));
            }
        }

        [Test]
        public void DecryptSignedSession()
        {
            var path = TestData(Location);
            var signpath = TestData(SignLocation);

            var material = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.signedsession.material")).First();
            var ciphertext = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.signedsession.ciphertext")).First();

            using (var crypter = new Crypter(path))
            using (var verifier = new AttachedVerifier(signpath))
            using (var sessionCrypter = new SessionCrypter(crypter, material, verifier))
            {
                var decrypted = sessionCrypter.Decrypt(ciphertext);
                Expect(decrypted, Is.EqualTo(Input));
            }
        }
    }
}