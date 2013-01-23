using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture]
    public class HmacFull : VerifierFullInterop
    {
        public HmacFull(string imp)
            : base(imp)
        {
            Location = "hmac";
        }
    }
}