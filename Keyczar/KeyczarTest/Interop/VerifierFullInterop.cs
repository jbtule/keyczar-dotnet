using System;
using System.IO;
using System.Linq;
using Keyczar;
using Keyczar.Compat;
using NUnit.Framework;

namespace KeyczarTest.Interop
{
    public abstract class VerifierFullInterop : Interop
    {
        protected string Location;

        public VerifierFullInterop(string imp)
            : base(imp)
        {
        }

        [Test]
        public void VerifyAttached()
        {
            var path = TestData(Location);
            using (var verifier = new AttachedVerifier(path))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.attached")).First();
                Expect(verifier.Verify(primarySignature), Is.True);
            }
        }

        [Test]
        public void VerifyAttachedSecret()
        {
            var path = TestData(Location);
            using (var verifier = new AttachedVerifier(path))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.secret.attached")).First();
                Expect(verifier.Verify(primarySignature, verifier.Config.RawStringEncoding.GetBytes("secret")), Is.True);
            }
        }

        [Test]
        public void VerifyTimeoutSucess()
        {
            Func<DateTime> earlyCurrentTimeProvider =
                () => new DateTime(2012, 12, 21, 11, 11, 0, DateTimeKind.Utc).AddMinutes(-5);

            var path = TestData(Location);
            using (var verifier = new TimeoutVerifier(path, earlyCurrentTimeProvider))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.timeout")).First();
                Expect(verifier.Verify(Input, primarySignature), Is.True);
            }
        }

        [Test]
        public void VerifyTimeoutExpired()
        {
            Func<DateTime> lateCurrentTimeProvider =
                () => new DateTime(2012, 12, 21, 11, 11, 0, DateTimeKind.Utc).AddMinutes(5);
            var path = TestData(Location);
            using (var verifier = new TimeoutVerifier(path, lateCurrentTimeProvider))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.timeout")).First();
                Expect(verifier.Verify(Input, primarySignature), Is.False);
            }
        }


        [Test]
        public void VerifyUnversioned()
        {
            var path = TestData(Location);
            using (var verifier = new VanillaVerifier(path))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.unversioned")).First();
                Expect(verifier.Verify(Input, primarySignature), Is.True);
            }
        }
    }
}