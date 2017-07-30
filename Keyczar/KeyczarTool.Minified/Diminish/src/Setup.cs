//Public Domain
//AssemblyResolve Concept from http://blogs.msdn.com/b/microsoft_press/archive/2010/02/03/jeffrey-richter-excerpt-2-from-clr-via-c-third-edition.aspx

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using KeyczarTool.Minified.Diminish.SevenZip;

namespace KeyczarTool.Minified.Diminish
{
    public static class Setup
    {
        private static readonly IDictionary<string, Assembly> _loaded = new Dictionary<string, Assembly>();

        public static Assembly AssemblyLoad(string asssemblyName)
        {
            var shortName = new AssemblyName(asssemblyName).Name;
            shortName = shortName.Replace(".resources", "");
            if (!_loaded.ContainsKey(shortName))
            {
                Func<string, string> resourceFormat =
                    ext =>
                    String.Format("KeyczarTool.Minified.Diminish.refs.{0}.{1}.dep-lzma", shortName, ext);

                var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFormat("dll"))
                             ?? Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFormat("exe"));
                if (stream == null)
                    throw new Exception(string.Format(
                        "Missing embedded dependency {0} was looking for resource {1} or {2}", asssemblyName,
                        resourceFormat("dll"), resourceFormat("exe")));
                using (stream)
                {
                    var pdb = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFormat("pdb"));
                    byte[] symbols = null;

                    if (pdb != null)
                    {
                        using (pdb)
                        using (var memStream = new MemoryStream())
                        {
                            Zipper.Decode(pdb, memStream);
                            symbols = memStream.ToArray();
                        }
                    }

                    using (var memStream = new MemoryStream())
                    {
                        Zipper.Decode(stream, memStream);
                        var assembly = symbols == null
                                           ? Assembly.Load(memStream.ToArray())
                                           : Assembly.Load(memStream.ToArray(), symbols);
                        _loaded.Add(shortName, assembly);
                    }
                }
            }
            return _loaded[shortName];
        }

        public static void Resolver()
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => AssemblyLoad(args.Name);
        }
    }
}