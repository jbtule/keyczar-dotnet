using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture("py3")]
    [TestFixture("cs")]
    [TestFixture("py")]
    [TestFixture("j")]
    [TestFixture("go")]
    public class RsaSignFull : PublicVerifierFullInterop
    {
        public RsaSignFull(string imp) : base(imp)
        {
            Location = "rsa-sign";
        }
    }
}