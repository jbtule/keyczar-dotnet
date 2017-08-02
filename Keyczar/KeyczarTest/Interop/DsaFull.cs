using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture]
    public class DsaFull : PublicVerifierFullInterop
    {
        public DsaFull(string imp)
            : base(imp)
        {
            Location = "dsa";
        }
    }
}