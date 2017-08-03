using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar;
using Keyczar.Util;
using ManyConsole;

namespace KeyczarTool.Commands
{
    public class Password : ConsoleCommand
    {
        private string _location;
        private bool _remove;

        public Password()
        {
            this.IsCommand("password", Localized.PasswordCommand);
            this.HasRequiredOption("l|location=", Localized.Location, v => { _location = v; });
            this.HasOption("r|remove", Localized.Remove, v => { _remove = true; });
            this.SkipsCommandSummaryBeforeRunning();
        }

        public override int Run(string[] remainingArguments)
        {
            IKeySet ks = new FileSystemKeySet(_location);


            bool add = !ks.Metadata.Encrypted;

            Func<string> prompt = CachedPrompt.Password(Util.PromptForPassword).Prompt;

            if (!add)
            {
                Console.WriteLine(Localized.PasswordPromptOldPassword);
                ks = new PbeKeySet(ks, prompt);
            }


            using (ks as PbeKeySet)
            using (var keySet = new MutableKeySet(ks))
            {
                keySet.ForceKeyDataChange();

                IKeySetWriter writer = new KeySetWriter(_location, overwrite: true);
                if (!_remove)
                {
                    Console.WriteLine(Localized.PasswordPromptNewPassword);
                    Func<string> newPrompt = CachedPrompt.Password(Util.DoublePromptForPassword).Prompt;
                    writer = new PbeKeySetWriter(writer, newPrompt);
                }
                else
                {
                    keySet.Metadata.Encrypted = false;
                }
                using (writer as PbeKeySetWriter)
                {
                    if (keySet.Save(writer))
                    {
                        if (_remove)
                            Console.WriteLine(Localized.MsgRemovedPassword);
                        else if (add)
                            Console.WriteLine(Localized.MsgAddedPasssword);
                        else
                            Console.WriteLine(Localized.MsgChangedPassword);
                        return 0;
                    }
                    return -1;
                }
            }
        }
    }
}