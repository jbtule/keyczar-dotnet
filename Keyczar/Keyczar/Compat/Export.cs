using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Keyczar.Compat
{
    /// <summary>
    /// Methods for exporting a keyset to a third party format
    /// </summary>
    public static class Export
    {
        static readonly SecureRandom Random = new SecureRandom();

        /// <summary>
        /// Exports the primary key as PKCS.
        /// </summary>
        /// <param name="keyset">The keyset.</param>
        /// <param name="location">The location.</param>
        /// <param name="passwordPrompt">The password prompt.</param>
        /// <returns></returns>
        /// <exception cref="InvalidKeyTypeException">Needs to be a private key.</exception>
        /// <exception cref="InvalidKeyTypeException">Non exportable key type.</exception>
        public static bool ExportPrimaryAsPKCS(this IKeySet keyset, string location, Func<string> passwordPrompt)
        {
            var i =keyset.Metadata.Versions.First(it => it.Status == KeyStatus.PRIMARY).VersionNumber;
            using (var key = keyset.GetKey(i))
            {
                if (!(key is IPrivateKey))
                {
                    throw new InvalidKeyTypeException("Needs to be a private key.");
                }

                using (var stream = new FileStream(location, FileMode.Create))
                using (var writer = new StreamWriter(stream))
                {
                    var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(writer);
                    AsymmetricKeyParameter writeKey;
                    if (key.Type == KeyType.DSA_PRIV)
                    {
                        var dsaKey = (DsaPrivateKey) key;
                        writeKey = new DsaPrivateKeyParameters(new BigInteger(dsaKey.X),
                                                               new DsaParameters(new BigInteger(dsaKey.PublicKey.P),
                                                                                 new BigInteger(dsaKey.PublicKey.Q),
                                                                                 new BigInteger(dsaKey.PublicKey.G)));

                    }
                    else if (key.Type == KeyType.RSA_PRIV)
                    {
                        var rsaKey = (RsaPrivateKey) key;
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

                    pemWriter.WriteObject(new Pkcs8Generator(writeKey, Pkcs8Generator.PbeSha1_RC2_128)
                                              {
                                                  Password = (passwordPrompt() ?? String.Empty).ToCharArray(),
                                                  SecureRandom = Random,
                                                  IterationCount = 4096
                                              });

                }
            }

            return true;
        }
    }
}
