using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture("py3")]
    [TestFixture("cs")]
    [TestFixture("py")]
    [TestFixture("j")]
    [TestFixture("go")]
    public class HmacFull : VerifierFullInterop
    {
        public HmacFull(string imp)
            : base(imp)
        {
            Location = "hmac";
        }
    }
}