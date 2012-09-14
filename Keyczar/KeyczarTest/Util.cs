using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KeyczarTest
{
    public static class Util
    {

        public static string TestDataPath(string baseDir, string topDir, string subDir =null)
        {
            if (String.IsNullOrWhiteSpace(topDir))
            {
                return baseDir;
            }

            return String.IsNullOrWhiteSpace(subDir)
                ? Path.Combine(baseDir, topDir)
                : Path.Combine(baseDir, subDir, topDir);
        }
    }
}
