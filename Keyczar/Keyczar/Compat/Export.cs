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
using Keyczar.Util;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System.Collections;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;

namespace Keyczar.Compat
{
    /// <summary>
    /// Methods for exporting a keyset to a third party format
    /// </summary>
    public static class Export
    {

        public static bool ExportAsPkcs12(this IKeySet keySet, string location, Func<string> passwordPrompt)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(location));
            using (var stream = new FileStream(location, FileMode.Create))
            {
                return ExportAsPkcs12(keySet, stream, passwordPrompt);
            }
        }

        public static bool ExportAsPkcs12(this IKeySet keySet, Stream saveStream, Func<string> passwordPrompt)
        {

            var issuerGenerator = new RsaKeyPairGenerator();
            issuerGenerator.Init(new KeyGenerationParameters(Secure.Random, 2048));

            var issuerKp = issuerGenerator.GenerateKeyPair();


            var issuercn = new X509Name($"CN=Keyczar|{keySet.Metadata.Name}|TEMPCA");
            var issuerGenertor = new X509V3CertificateGenerator();
            BigInteger issueSerialNumber = BigInteger.ProbablePrime(128, Secure.Random);
            issuerGenertor.SetSerialNumber(issueSerialNumber);
            issuerGenertor.SetSubjectDN(issuercn);
            issuerGenertor.SetIssuerDN(issuercn);
            issuerGenertor.SetNotAfter(DateTime.Now.AddYears(100));
            issuerGenertor.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            issuerGenertor.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.AnyExtendedKeyUsage));
            issuerGenertor.SetPublicKey(issuerKp.Public);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", issuerKp.Private, Secure.Random);
            var issuerCert = issuerGenertor.Generate(signatureFactory);

            var builder = new Pkcs12StoreBuilder();

            var store = builder.Build();

            var issueEntryCert = new X509CertificateEntry(issuerCert);
            var hasPrivateKeys = false;

            foreach (var version in keySet.Metadata.Versions)
            {
                using (var key = keySet.GetKey(version.VersionNumber))
                {
                    var cn = new X509Name($"CN=Keyczar|{keySet.Metadata.Name}|{version.VersionNumber}");
                    var certificateGenerator = new X509V3CertificateGenerator();
                    BigInteger serialNo = BigInteger.ProbablePrime(128, Secure.Random);
                    certificateGenerator.SetSerialNumber(serialNo);
                    certificateGenerator.SetSubjectDN(cn);
                    certificateGenerator.SetIssuerDN(issuercn);
                    certificateGenerator.SetNotAfter(DateTime.Now.AddYears(100));
                    certificateGenerator.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
                    certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.AnyExtendedKeyUsage));
                    switch (key)
                    {

                        case IRsaPrivateKey k:
                            {
                                hasPrivateKeys = true;
                                var publicKey = BouncyCastleFromKey(k.PublicKey);
                                var privateKey = BouncyCastleFromKey(k);

                                certificateGenerator.SetPublicKey(publicKey);
                                var certificate = certificateGenerator.Generate(signatureFactory);

                                var entryCert = new X509CertificateEntry(certificate);
                                store.SetCertificateEntry(certificate.SubjectDN.ToString(), entryCert);

                                var keyEntry = new AsymmetricKeyEntry(privateKey);
                                store.SetKeyEntry(certificate.SubjectDN.ToString() + "_key", keyEntry, new X509CertificateEntry[] { entryCert, issueEntryCert });
                            }
                            break;
                        case IRsaPublicKey rsaPub:
                            {
                                var publicKey = BouncyCastleFromKey(rsaPub);
                                certificateGenerator.SetPublicKey(publicKey);
                                var certificate = certificateGenerator.Generate(signatureFactory);
                                var entryCert = new X509CertificateEntry(certificate);
                                store.SetCertificateEntry(certificate.SubjectDN.ToString(), entryCert);

                            }
                            break;
                        case DsaPrivateKey dsaKey:
                            {
                                hasPrivateKeys = true;
                                var publicKey = BouncyCastleFromKey(dsaKey.PublicKey);
                                var privateKey = BouncyCastleFromKey(dsaKey);
                                certificateGenerator.SetPublicKey(publicKey);
                                var certificate = certificateGenerator.Generate(signatureFactory);

                                var entryCert = new X509CertificateEntry(certificate);
                                store.SetCertificateEntry(certificate.SubjectDN.ToString(), entryCert);

                                var keyEntry = new AsymmetricKeyEntry(privateKey);
                                store.SetKeyEntry(certificate.SubjectDN.ToString() + "|key", keyEntry, new X509CertificateEntry[] { entryCert, issueEntryCert });
                            }
                            break;
                        case DsaPublicKey dsaKey:
                            {
                                var publicKey = BouncyCastleFromKey(dsaKey);
                                certificateGenerator.SetPublicKey(publicKey);
                                var certificate = certificateGenerator.Generate(signatureFactory);
                                var entryCert = new X509CertificateEntry(certificate);
                                store.SetCertificateEntry(certificate.SubjectDN.ToString(), entryCert);
                            }
                            break;
                    }
                }
            }


            if (!hasPrivateKeys)
            {
                passwordPrompt = null;
            }
            var password = passwordPrompt?.Invoke();
            if (String.IsNullOrEmpty(password))
            {
                password = null;
            }

            store.Save(saveStream, password?.ToCharArray(), new SecureRandom());

            return true;
        }


		/// <summary>
		/// Exports the primary key as PKCS.
		/// </summary>
		/// <param name="keySet">The keyset.</param>
		/// <param name="location">The location.</param>
		/// <param name="passwordPrompt">The password prompt.</param>
		/// <returns></returns>
		/// <exception cref="InvalidKeyTypeException">Needs to be a private key.</exception>
		/// <exception cref="InvalidKeyTypeException">Non exportable key type.</exception>
		public static bool ExportPrimaryAsPkcs(this IKeySet keySet, string location, Func<string> passwordPrompt)
		{
			Directory.CreateDirectory(Path.GetDirectoryName(location));
			using (var stream = new FileStream(location, FileMode.Create))
			{
				return ExportPrimaryAsPkcs(keySet, stream, passwordPrompt);
			}
		}


		/// <summary>
		/// Exports the primary key as PKCS.
		/// </summary>
		/// <param name="keySet">The keyset.</param>
		/// <param name="stream">The stream to write too.</param>
		/// <param name="passwordPrompt">The password prompt.</param>
		/// <returns></returns>
		/// <exception cref="InvalidKeyTypeException">Needs to be a private key.</exception>
		/// <exception cref="InvalidKeyTypeException">Non exportable key type.</exception>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2202:Do not dispose objects multiple times")]
        public static bool ExportPrimaryAsPkcs(this IKeySet keySet, Stream stream, Func<string> passwordPrompt)
        {
          
            using (var key = keySet.GetPrimaryKey())
            {
                using (var writer = new StreamWriter(stream))
                {
                    var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(writer);

                    var password = (passwordPrompt?.Invoke() ?? String.Empty);
                    AsymmetricKeyParameter writeKey;
                    if (!(key is IPrivateKey) || String.IsNullOrWhiteSpace(password))
                    {

                        switch (key)
                        {
                            case DsaPublicKey dsa:
                                writeKey = BouncyCastleFromKey(dsa);
                                break;
                            case IRsaPublicKey rsa:
                                writeKey = BouncyCastleFromKey(rsa);
                                break;
                            case DsaPrivateKey dsa:
                                writeKey = BouncyCastleFromKey(dsa.PublicKey);
                                pemWriter.WriteObject(new MiscPemGenerator(writeKey));
                                writeKey = BouncyCastleFromKey(dsa);
                                break;
                            case IRsaPrivateKey rsa:
                                writeKey = BouncyCastleFromKey(rsa.PublicKey);
                                pemWriter.WriteObject(new MiscPemGenerator(writeKey));
                                writeKey = BouncyCastleFromKey(rsa);
                                break;
                            default:
                                throw new InvalidKeyTypeException("Non exportable key type.");
                        }

                        pemWriter.WriteObject(new MiscPemGenerator(writeKey));
                    }
                    else
                    {
                        switch (key)
                        {
                            case DsaPrivateKey dsa:
                                writeKey = BouncyCastleFromKey(dsa);
                                break;
                            case IRsaPrivateKey rsa:
                                writeKey = BouncyCastleFromKey(rsa);
                                break;
                            default:
                                throw new InvalidKeyTypeException("Non exportable key type.");
                        }

                        pemWriter.WriteObject(new Pkcs8Generator(writeKey, Pkcs8Generator.PbeSha1_RC2_128)
                        {
                            Password = (password).ToCharArray(),
                            SecureRandom = Secure.Random,
                            IterationCount = 4096
                        });
                    }
                }
            }

            return true;
        }

        internal static RsaPrivateCrtKeyParameters BouncyCastleFromKey(IRsaPrivateKey key)
        {
            return new RsaPrivateCrtKeyParameters(
                                key.PublicKey.Modulus.ToBouncyBigInteger(),
                                key.PublicKey.PublicExponent.ToBouncyBigInteger(),
                                key.PrivateExponent.ToBouncyBigInteger(),
                                key.PrimeP.ToBouncyBigInteger(),
                                key.PrimeQ.ToBouncyBigInteger(),
                                key.PrimeExponentP.ToBouncyBigInteger(),
                                key.PrimeExponentQ.ToBouncyBigInteger(),
                                key.CrtCoefficient.ToBouncyBigInteger());
        }

        internal static RsaKeyParameters BouncyCastleFromKey(IRsaPublicKey key)
        {
            return new RsaKeyParameters(false,
                                        key.Modulus.ToBouncyBigInteger(),
                                        key.PublicExponent.ToBouncyBigInteger()); ;
        }

        internal static DsaPublicKeyParameters BouncyCastleFromKey(DsaPublicKey key)
        {
            return new DsaPublicKeyParameters(key.Y.ToBouncyBigInteger(),
                                                                  new DsaParameters(
                                                                      key.P.ToBouncyBigInteger(),
                                                                      key.Q.ToBouncyBigInteger(),
                                                                      key.G.ToBouncyBigInteger()));
        }

        internal static DsaPrivateKeyParameters BouncyCastleFromKey(DsaPrivateKey key)
        {
            return new DsaPrivateKeyParameters(key.X.ToBouncyBigInteger(),
                                                                   new DsaParameters(
                                                                       key.PublicKey.P.ToBouncyBigInteger(),
                                                                       key.PublicKey.Q.ToBouncyBigInteger(),
                                                                       key.PublicKey.G.ToBouncyBigInteger()));
        }
    }
}