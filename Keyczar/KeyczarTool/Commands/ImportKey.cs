using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Util;
using ManyConsole;

namespace KeyczarTool
{
    internal class ImportKey : ConsoleCommand
    {
        private string _location;
        private string _importLocation;
        private KeyStatus _status;
        private string _crypterLocation;
        private bool _password;
        private bool _force;

        public ImportKey()
        {
            this.IsCommand("importkey", Localized.ImportKey);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasOption("f|force", Localized.KeyType, v => { _force = true; });
            this.HasRequiredOption("i|importlocation=", Localized.ImportLocation, v => { _importLocation = v; });
            this.HasRequiredOption("s|status=", Localized.Status, v => { _status = v; });
            this.HasOption("c|crypter=", Localized.Crypter, v => { _crypterLocation = v; });
            this.HasOption("p|password", Localized.Password, v => { _password = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            var ret = 0;
            Crypter crypter = null;
            IKeySet ks = new FileSystemKeySet(_location);

            Func<string> singlePrompt = CachedPrompt.Password(() =>
                                                                  {
                                                                      Console.WriteLine(Localized.MsgForKeySet);
                                                                      return Util.PromptForPassword();
                                                                  }).Prompt;

            var prompt = ks.Metadata.Encrypted
                             ? singlePrompt
                             : CachedPrompt.Password(() =>
                                                         {
                                                             Console.WriteLine(Localized.MsgForKeySet);
                                                             return Util.PromptForPassword();
                                                         }).Prompt;

            IDisposable dks = null;
            if (!String.IsNullOrWhiteSpace(_crypterLocation))
            {
                if (_password)
                {
                    var cks =  KeySet.LayerSecurity(FileSystemKeySet.Creator(_crypterLocation),
                                              PbeKeySet.Creator(singlePrompt));
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
            using (var keySet = new MutableKeySet(ks))
            {
                if (_status != KeyStatus.Primary && _status != KeyStatus.Active)
                {
                    Console.WriteLine("{0} {1}.", Localized.Status, _status.Identifier);
                    return -1;
                }
                ImportedKeySet importedKeySet = null;
                try
                {
                    importedKeySet = ImportedKeySet.Import.X509Certificate(keySet.Metadata.Purpose, _importLocation);
                }
                catch
                {
                    importedKeySet = ImportedKeySet.Import.PkcsKey(
                        keySet.Metadata.Purpose, _importLocation,
                        CachedPrompt.Password(() =>
                                                  {
                                                      Console.WriteLine(Localized.MsgForImport);
                                                      return Util.PromptForPassword();
                                                  }).Prompt);
                }
                if (importedKeySet == null)
                {
                    Console.WriteLine(Localized.MsgUnparsableImport);
                    ret = -1;
                }
                else
                {


                    if (keySet.Metadata.OriginallyOfficial && keySet.Metadata.ValidOfficial())
                    {
                        var importedKeyType = importedKeySet.Metadata.OfficialKeyType();
                        var keySetKeyType = keySet.Metadata.OfficialKeyType();
                        if (importedKeyType != keySetKeyType && !_force)
                        {
                            ret = -1;
                            Console.WriteLine(Localized.MsgMismatchedType,
                                importedKeyType,
                                keySetKeyType);
                        }
                    }

                    if (keySet.Metadata.Kind != importedKeySet.Metadata.Kind)
                    {
                        if (!keySet.Metadata.Versions.Any())
                        {
                            keySet.Metadata.Kind = importedKeySet.Metadata.Kind;
                        }
                        else
                        {
                            ret = -1;
                            Console.WriteLine(Localized.MsgConflictingKeyTypes,
                                              keySet.Metadata.Kind.Identifier,
                                              importedKeySet.Metadata.Kind);
                        }
                    }

                    using (importedKeySet)
                    {
                        if (ret != -1)
                        {
                            var count = importedKeySet.Metadata.Versions.Count();
                            var outMsg = "";
                            foreach (var v in importedKeySet.Metadata.Versions)
                            {
                                var status = v.Status;
                                if(count == 1 || _status != KeyStatus.Primary ){
                                    status = _status;
                                }

                                var ver = keySet.AddKey(status, importedKeySet.GetKey(v.VersionNumber));
                                outMsg = ver.ToString();
                            }
                            if(count>1){
                                outMsg = $"{count} keys";
                            }


                            IKeySetWriter writer = new FileSystemKeySetWriter(_location, overwrite: true);

                            if (crypter != null)
                            {
                                writer = new EncryptedKeySetWriter(writer, crypter);
                            }
                            else if (_password)
                            {
                                writer = new PbeKeySetWriter(writer, prompt);
                            }

                            if (keySet.Save(writer))
                            {
                                Console.WriteLine("{0} {1}.", Localized.MsgImportedNewKey, outMsg);
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

            return ret;
        }
    }
}