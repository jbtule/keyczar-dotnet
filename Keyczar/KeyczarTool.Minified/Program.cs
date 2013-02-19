using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace KeyczarTool.Minified
{
    internal class Program
    {
        private static int Main(string[] arguments)
        {
            return Diminish.Main<int>.Call<string[]>("KeyczarTool", "KeyczarTool.Program")(arguments);
        }
    }
}