using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using ManyConsole;
using Keyczar.Compat;
namespace KeyczarTool.Commands
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

            if (!ks.ExportPrimaryAsPKCS(_destination, () =>
                                                      {
                                                          int i = 0;
                                                          while (i++<4)
                                                            {
                                                                Console.WriteLine("Please enter passphrase:");
                                                                var phrase1 = Console.ReadLine();
                                                                Console.WriteLine("Please re-enter passphrase:");
                                                                var phrase2 = Console.ReadLine();

                                                                if (phrase1.Equals(phrase2))
                                                                {
                                                                    return phrase1;
                                                                }
                                                                Console.WriteLine("Passphrase didn't match.");
                                                            } 
                                                          Console.WriteLine("Giving up.");
                                                          throw new Exception("Entered non matching password too many times");
                                                      }))
            {
                ret = -1;
            }

            if (crypter != null)
                crypter.Dispose();

            return ret;
        }
    }
}
