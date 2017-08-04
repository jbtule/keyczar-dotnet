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
            this.IsCommand("keytypes", Localized.KeyTypes);
            this.HasOption("u|unofficial", Localized.KeyTypes_Unofficial, v => { _unofficial = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }


        public override int Run(string[] remainingArguments)
        {

            string officialDefault = "*";
            if (_unofficial)
            {
                officialDefault = "";
            }

            Console.WriteLine(Localized.KeyTypes_Run_Encrypt_and_Decrypt_);
            Console.WriteLine(Localized.KeyTypes_Run___Symmetric_);
            Console.WriteLine($"    AES_HMAC_SHA1{officialDefault}  (128*,192,256)");
            if (_unofficial)
            {
                Console.WriteLine("    AES_GCM*  (256*,192,128) -unofficial");
                Console.WriteLine("    AES_HMAC_SHA2*  (128*, 192, 256) -unofficial");
            }
            Console.WriteLine(Localized.KeyTypes_Run___Asymmetric_);
            Console.WriteLine("    RSA*  (2048*, 4096, 1024)");
            Console.WriteLine(Localized.KeyTypes_Run_Sign_and_Verify_);
            Console.WriteLine(Localized.KeyTypes_Run___Symmetric_);
            Console.WriteLine($"    HMAC_SHA11{officialDefault}  (256*)");
            if (_unofficial)
            {
                Console.WriteLine("    HMAC_SHA2*  (128*, 192, 256) -unofficial");
            }
            Console.WriteLine(Localized.KeyTypes_Run___Asymmetric_);
            Console.WriteLine($"    DSA_SHA1{officialDefault}  (1024*)");
            Console.WriteLine("    RSA_SHA1  (2048*, 4096, 1024)");
            if (_unofficial)
            {
                Console.WriteLine("    RSA_PSS*  (2048*, 4096, 3072, 1024) -unofficial");
            }
            Console.WriteLine();
            Console.WriteLine(Localized.KeyTypes_Run____denotes_default_);
            return 0;
        }
    }
}
