using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Keyczar.Compat
{
    public static class Export
    {
        static SecureRandom Random = new SecureRandom();

        public static bool ExportPrimaryAsPKCS(this IKeySet keyset, string location, Func<string> passPhrase)
        {
            var i =keyset.Metadata.Versions.First(it => it.Status == KeyStatus.PRIMARY).VersionNumber;
            var key =keyset.GetKey(i);
            if (!(key is IPrivateKey))
            {
                throw new InvalidKeyTypeException("Needs to be a private key.");
            }

            using (var stream = File.OpenWrite(location))
            using (var writer = new StreamWriter(stream))
            {
                var pemWriter = new PemWriter(writer);
                object writeKey;
                if (key.Type == KeyType.DSA_PRIV)
                {
                    var dsaKey = (DsaPrivateKey)key;
                    writeKey = new DsaPrivateKeyParameters(new BigInteger(dsaKey.X),
                                                           new DsaParameters(new BigInteger(dsaKey.PublicKey.P),
                                                                             new BigInteger(dsaKey.PublicKey.Q),
                                                                             new BigInteger(dsaKey.PublicKey.G)));

                }
                else if (key.Type == KeyType.RSA_PRIV)
                {
                    var rsaKey = (RsaPrivateKey)key;
                    writeKey = new RsaPrivateCrtKeyParameters(
                       new BigInteger(rsaKey.PublicKey.Modulus),
                       new BigInteger(rsaKey.PublicKey.PublicExponent),
                       new BigInteger(rsaKey.PrivateExponent),
                       new BigInteger(rsaKey.PrimeP),
                       new BigInteger(rsaKey.PrimeQ),
                       new BigInteger(rsaKey.PrimeExponentP),
                       new BigInteger(rsaKey.PrimeExponentQ),
                       new BigInteger(rsaKey.CrtCoefficient));
                }
                else
                {
                    throw new InvalidKeyTypeException("Non exportable key type.");
                }


                pemWriter.WriteObject(writeKey, "AES-CBC", passPhrase().ToCharArray(), Random);
            }

            return true;
        }
    }
}
