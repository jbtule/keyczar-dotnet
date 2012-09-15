using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using ManyConsole;
using Keyczar.Compat;
namespace KeyczarTool
{
    class Export : ConsoleCommand
    {
        private string _destination;
        private string _location;
        private string _crypterLocation;

        public Export()
        {
            this.IsCommand("export", "Exports primary private key to a PKCS Pem file.");
            this.HasRequiredOption("l|location=", "The location of the private key set.", v => { _location = v; });
            this.HasRequiredOption("d|destination=", "The destination of the public key set.", v => { _destination = v; });
            this.HasOption("c|crypter=", "The location of the crypter to decrypt private key set.", v => { _crypterLocation = v; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new KeySet(_location);
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                crypter = new Crypter(_crypterLocation);
                ks = new EncryptedKeySet(ks, crypter);
            }

            if (!ks.ExportPrimaryAsPKCS(_destination, Util.DoublePromptForPassword))
            {
                ret = -1;
            }else
            {
                Console.WriteLine("Exported to pem.");
            }

            

            if (crypter != null)
                crypter.Dispose();

            return ret;
        }
    }
}
