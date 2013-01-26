using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ManyConsole;

namespace KeyczarTool.Commands
{
    public class KeyTypes : ConsoleCommand
    {
        private bool _unofficial;
        public KeyTypes()
        {
            this.IsCommand("keytypes", "List available key types.");
            this.HasOption("u|unofficial", "Also list available unofficial key types.", v => { _unofficial = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }


        public override int Run(string[] remainingArguments)
        {
            Console.WriteLine("Encrypt and Decrypt:");
            Console.WriteLine("  Symmetric:");
            Console.WriteLine("    AES_HMAC_SHA1*  (128*,192,256)");
            if (_unofficial)
            {
                Console.WriteLine("    AES_GCM  (256*,192,128) -unofficial");
            }
            Console.WriteLine("  Asymmetric:");
            Console.WriteLine("    RSA*  (2048*, 4096, 1024)");
            Console.WriteLine("Sign and Verify:");
            Console.WriteLine("  Symmetric:");
            Console.WriteLine("    HMAC_SHA1*  (256*)");
            Console.WriteLine("  Asymmetric:");
            Console.WriteLine("    DSA_SHA1*  (1024*)");
            Console.WriteLine("    RSA_SHA1  (2048*, 4096, 1024)");
            Console.WriteLine();
            Console.WriteLine(" * denotes default.");
            return 0;
        }
    }
}
