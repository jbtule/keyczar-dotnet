using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace KeyczarTool.Minified
{
    class Program
    {

        static int Main(string[] arguments)
        {
            return Diminish.Main<int>.Call<string[]>("KeyczarTool","KeyczarTool.Program")(arguments);
        }
    }
}
