using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture("py3")]
    [TestFixture("cs")]
    [TestFixture("py")]
    [TestFixture("j")]
    [TestFixture("go")]
    public class DsaFull : PublicVerifierFullInterop
    {
        public DsaFull(string imp)
            : base(imp)
        {
            Location = "dsa";
        }
    }
}