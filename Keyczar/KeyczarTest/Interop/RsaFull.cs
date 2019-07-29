using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture("py3")]
    [TestFixture("cs")]
    [TestFixture("py")]
    [TestFixture("j")]
    [TestFixture("go")]
    public class RsaFull : CrypterFullInterop
    {
        public RsaFull(string imp)
            : base(imp)
        {
            Location = "rsa";
            SignLocation = "dsa.public";
        }
    }
}