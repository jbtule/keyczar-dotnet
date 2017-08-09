using System;
using System.Configuration;
using System.Text;

namespace Keyczar
{
    public class KeyczarConfig
    {

        public KeyczarConfig(){
            StrictDsaVerification = Convert.ToBoolean(ConfigurationManager.AppSettings["keyczar.strict_dsa_verification"] ?? "false");
            RawStringEncoding = Encoding.GetEncoding(ConfigurationManager.AppSettings["keyczar.raw_string_encoding"] ?? "utf-8");

        }

        /// <summary>
        /// To be compatable with Java, by default ignores specific parsable, but bad DSA sigs. 
        /// Can turn on strit checking with the App Setting "keyczar.strict_dsa_verification"
        /// </summary>
        public bool StrictDsaVerification { get; set; }
        public Encoding RawStringEncoding { get; set; }
    }
}