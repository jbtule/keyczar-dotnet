using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Compat;
using ManyConsole;

namespace KeyczarTool
{
    class ImportKey : ConsoleCommand
    {
        private string _location;
        private string _importLocation;
        private KeyStatus _status;
        private string _crypterLocation;
        private string _passphrase;

        public ImportKey()
        {
            this.IsCommand("importkey", "Imports a key into to an existing key set.");
            this.HasRequiredOption("l|location=", "The location of the key set.", v => { _location = v; });
            this.HasRequiredOption("i|importlocation=", "The location of the import file.", v => { _importLocation = v; });
            this.HasOption("s|status=", "The status (active|primary).", v => { _status = v; });
            this.HasOption("c|crypter=", "The crypter key set location.", v => { _crypterLocation = v; });
            this.HasOption("p|passphrase=", "The import files passphrase.", v => { _passphrase = v; });
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

            using (var keySet = new MutableKeySet(ks))
            {
                 if(_status != KeyStatus.PRIMARY && _status != KeyStatus.ACTIVE)
                 {
                     Console.WriteLine("Invalid status:{0}",_status.Identifier);
                     return -1;
                 }
                ImportedKeySet importedKeySet = null;
                try
                {
                    importedKeySet = ImportedKeySet.Import.X509Certificate(keySet.Metadata.Purpose, _importLocation);
                }
                catch
                {
                    importedKeySet = ImportedKeySet.Import.PkcsKey(keySet.Metadata.Purpose, _importLocation,_passphrase);
                }
                if (importedKeySet == null)
                {
                    Console.WriteLine("unparsable import file.");
                    ret = -1;
                }
                else
                {
                    if (keySet.Metadata.Type != importedKeySet.Metadata.Type)
                    {
                        if (!keySet.Metadata.Versions.Any())
                        {
                            keySet.Metadata.Type = importedKeySet.Metadata.Type;
                        }
                        else
                        {
                            ret = -1;
                            Console.WriteLine("conflicting key types. {0} != {1}",
                                              keySet.Metadata.Type.Identifier,
                                              importedKeySet.Metadata.Type);
                        }
                    }
                   
                    using (importedKeySet)
                    {
                        if (ret != -1)
                            {
                            var ver = keySet.AddKey(_status, importedKeySet.GetKey(1));


                            IKeySetWriter writer = new KeySetWriter(_location, overwrite: true);

                            if (crypter != null)
                            {
                                writer = new EncryptedKeySetWriter(writer, crypter);
                            }

                            if (keySet.Save(writer))
                            {
                                Console.WriteLine("Imported new key version:{0}", ver);
                                ret = 0;
                            }
                            else
                            {
                                ret = -1;

                            }
                        }
                    }
                }
            }

            if(crypter !=null)
                crypter.Dispose();

            return ret;
        }
    }
}
