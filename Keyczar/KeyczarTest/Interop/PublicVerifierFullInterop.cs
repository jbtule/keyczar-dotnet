using System;
using System.IO;
using System.Linq;
using Keyczar;
using Keyczar.Compat;
using NUnit.Framework;

namespace KeyczarTest.Interop
{
    public abstract class PublicVerifierFullInterop : VerifierFullInterop
    {
        public PublicVerifierFullInterop(string imp)
            : base(imp)
        {
        }

        [Test]
        public void PublicVerifyAttached()
        {
            var path = TestData(Location);
            using (var verifier = new AttachedVerifier(path + ".public"))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.attached")).First();
                Expect(verifier.Verify(primarySignature), Is.True);
            }
        }

        [Test]
        public void PublicVerifyAttachedSecret()
        {
            var path = TestData(Location);
            using (var verifier = new AttachedVerifier(path + ".public"))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.secret.attached")).First();
                Expect(verifier.Verify(primarySignature, Keyczar.Keyczar.RawStringEncoding.GetBytes("secret")), Is.True);
            }
        }

        [Test]
        public void PublicVerifyTimeoutSucces()
        {
            var path = TestData(Location);

            Func<DateTime> earlyCurrentTimeProvider =
                () => new DateTime(2012, 12, 21, 11, 11, 0, DateTimeKind.Utc).AddMinutes(-5);

            using (var verifier = new TimeoutVerifier(path + ".public", earlyCurrentTimeProvider))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.timeout")).First();
                Expect(verifier.Verify(Input, primarySignature), Is.True);
            }
        }

        [Test]
        public void PublicVerifyTimeoutExpired()
        {
            Func<DateTime> lateCurrentTimeProvider =
                () => new DateTime(2012, 12, 21, 11, 11, 0, DateTimeKind.Utc).AddMinutes(5);
            var path = TestData(Location);
            using (var verifier = new TimeoutVerifier(path + ".public", lateCurrentTimeProvider))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.timeout")).First();
                Expect(verifier.Verify(Input, primarySignature), Is.False);
            }
        }


        [Test]
        public void PublicVerifyUnversioned()
        {
            var path = TestData(Location);
            using (var verifier = new VanillaVerifier(path + ".public"))
            {
                var primarySignature = (WebBase64) File.ReadAllLines(Path.Combine(path, "2.unversioned")).First();
                Expect(verifier.Verify(Input, primarySignature), Is.True);
            }
        }
    }
}