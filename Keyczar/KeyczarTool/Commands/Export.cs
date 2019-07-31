using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Util;
using ManyConsole.CommandLineUtils;
using Keyczar.Compat;

namespace KeyczarTool
{
    internal class Export : ConsoleCommand
    {
        private string _destination;
        private string _location;
        private string _crypterLocation;
        private bool _password;
        private bool _pkcs12;

        public Export()
        {
            this.IsCommand("export", Localized.Export);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasRequiredOption("d|destination=", Localized.Destination, v => { _destination = v; });
            this.HasOption("pkcs12", Localized.Pksc12Flag, v => { _pkcs12 = true; } );
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new FileSystemKeySet(_location);

            Func<string> prompt = CachedPrompt.Password(() =>
                                                            {
                                                                Console.WriteLine(Localized.MsgForKeySet);
                                                                return Util.PromptForPassword();
                                                            }).Prompt;

            IDisposable dks = null;
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                if (_password)
                {
                    var cks = KeySet.LayerSecurity(FileSystemKeySet.Creator(_crypterLocation),
                                                   PbeKeySet.Creator(prompt)
                                                  );
                    crypter = new Crypter(cks);
                    dks = cks;
                }
                else
                {
                    crypter = new Crypter(_crypterLocation);
                }
                ks = new EncryptedKeySet(ks, crypter);
            }
            else if (_password)
            {
                ks = new PbeKeySet(ks, prompt);
            }
            var d2ks = ks as IDisposable;


            using (crypter)
            using (dks)
            using (d2ks)
            {
                if (_pkcs12)
                {
                    if (!ks.ExportAsPkcs12(_destination, CachedPrompt.Password(() =>
                                                    {
                                                        Console.WriteLine(Localized.MsgForExport);
                                                        return Util.DoublePromptForPassword
                                                                ();
                                                    }).Prompt))
                    {
                        ret = -1;
                    }
                    else
                    {
                        Console.WriteLine(Localized.MsgExportedPem);
                    }
                } else {
                    if (!ks.ExportPrimaryAsPkcs(_destination, CachedPrompt.Password(() =>
                    {
                        Console.WriteLine(Localized.MsgForExport);
                        return Util.DoublePromptForPassword();
                    }).Prompt))
                    {
                        ret = -1;
                    }
                    else
                    {
                        Console.WriteLine(Localized.MsgExportedPem);
                    }
                }
            }


            return ret;
        }
    }
}