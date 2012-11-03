using System;
using System.Reflection;

namespace KeyczarTool.Minified.Diminish
{
    public static class Main<TReturn>
    {
        public static Func<TArgs,TReturn> Call<TArgs>(string assemblyName, string typeName, string entryMethod="Main")
        {
            return arg =>
                       {
                           Setup.Resolver();
                           var assembly =Setup.AssemblyLoad(assemblyName);
                           var type = assembly.GetType(typeName);
                           var method = type.GetMethod(entryMethod,BindingFlags.Static|BindingFlags.Public);
                           return (TReturn)method.Invoke(null, arg == null ? null : new object[] { arg });
                       };
        }

        public static Func<TReturn> Call(string assemblyName, string typeName, string entryMethod = "Main")
        {
            return () => Call<object>(assemblyName, typeName, entryMethod)(null);
        } 
    }
}
