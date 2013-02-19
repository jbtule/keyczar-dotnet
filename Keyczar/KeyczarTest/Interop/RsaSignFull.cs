using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture]
    public class RsaSignFull : PublicVerifierFullInterop
    {
        public RsaSignFull(string imp) : base(imp)
        {
            Location = "rsa-sign";
        }
    }
}