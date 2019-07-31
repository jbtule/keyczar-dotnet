using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Crypto;
using ManyConsole.CommandLineUtils;

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

       

            var keyTypeSpecs = KeyType.Specs.Where(it=>!it.Public && !it.Temp).ToList();

            void writeTypes(bool symmetric, bool encrypt)
            {
                
                var dummyMetaData = new KeyMetadata();
                dummyMetaData.OriginallyOfficial = !_unofficial;
                dummyMetaData.Kind = symmetric ? KeyKind.Symmetric : KeyKind.Private;
                dummyMetaData.Purpose = encrypt ? KeyPurpose.DecryptAndEncrypt : KeyPurpose.SignAndVerify;
                
                
                
                var keyInterface = encrypt ? typeof(IEncrypterKey) : typeof(ISignerKey);
                
                foreach (var t in  keyTypeSpecs.Where(it=> (!it.Unofficial || _unofficial)
                                                           && (it.Asymmetric ^ symmetric)
                                                           && keyInterface.IsAssignableFrom(it.RepresentedType)))
                {
                    var isDefault = t.Name == dummyMetaData.DefaultKeyType ? "*" : " ";
                    var sizes = String.Join(",",t.KeySizes.Select((it, i) => it.ToString() + (i == 0 ? "*" : "")));
    
                    var map = AddKey.KeyTypeMaps.FirstOrDefault(it => it.Item1 == t.Name);
    
                    if (map == null)
                    {
                        throw new Exception($"Missing map for {t.Name}");
                    }
                    
                    // ReSharper disable once LocalizableElement
                    Console.WriteLine($"    {(map.Item2 + isDefault).PadRight(14)} ({sizes})");
                }
            }



            Console.WriteLine(Localized.KeyTypes_Run_Encrypt_and_Decrypt_);
            Console.WriteLine(Localized.KeyTypes_Run___Symmetric_);
            writeTypes(symmetric: true, encrypt: true);
            
            
            Console.WriteLine(Localized.KeyTypes_Run___Asymmetric_);
            writeTypes(symmetric: false, encrypt: true);

            Console.WriteLine(Localized.KeyTypes_Run_Sign_and_Verify_);
            Console.WriteLine(Localized.KeyTypes_Run___Symmetric_);
            writeTypes(symmetric: true, encrypt: false);

            Console.WriteLine(Localized.KeyTypes_Run___Asymmetric_);
            writeTypes(symmetric: false, encrypt: false);

            Console.WriteLine();
            Console.WriteLine(Localized.KeyTypes_Run____denotes_default_);
            return 0;
        }
    }
}
