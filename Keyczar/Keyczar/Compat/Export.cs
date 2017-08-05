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
            using (var stream = new FileStream(location, FileMode.Create)){
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
                                var publicKey = new RsaKeyParameters(false,
                                                                     k.PublicKey.Modulus.ToBouncyBigInteger(),
                                                                     k.PublicKey.PublicExponent.ToBouncyBigInteger());

                                var privateKey = new RsaPrivateCrtKeyParameters(
                                                      k.PublicKey.Modulus
                                                               .ToBouncyBigInteger(),
                                                      k.PublicKey.PublicExponent
                                                               .ToBouncyBigInteger(),
                                                      k.PrivateExponent.ToBouncyBigInteger
                                                          (),
                                                      k.PrimeP.ToBouncyBigInteger(),
                                                      k.PrimeQ.ToBouncyBigInteger(),
                                                      k.PrimeExponentP.ToBouncyBigInteger(),
                                                      k.PrimeExponentQ.ToBouncyBigInteger(),
                                                        k.CrtCoefficient.ToBouncyBigInteger());

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
                                var publicKey = new RsaKeyParameters(false,
                                                                     rsaPub.Modulus.ToBouncyBigInteger(),
                                                                     rsaPub.PublicExponent.ToBouncyBigInteger());
                                certificateGenerator.SetPublicKey(publicKey);
                                var certificate = certificateGenerator.Generate(signatureFactory);
                                var entryCert = new X509CertificateEntry(certificate);
                                store.SetCertificateEntry(certificate.SubjectDN.ToString(), entryCert);

                            }
                            break;
                        case DsaPrivateKey dsaKey:
                            {
                                hasPrivateKeys = true;

                                var publicKey = new DsaPublicKeyParameters(dsaKey.PublicKey.Y.ToBouncyBigInteger(),
                                                               new DsaParameters(
                                                                   dsaKey.PublicKey.P.ToBouncyBigInteger(),
                                                                   dsaKey.PublicKey.Q.ToBouncyBigInteger(),
                                                                   dsaKey.PublicKey.G.ToBouncyBigInteger()));

                                var privateKey = new DsaPrivateKeyParameters(dsaKey.X.ToBouncyBigInteger(),
                                                                   new DsaParameters(
                                                                       dsaKey.PublicKey.P.ToBouncyBigInteger(),
                                                                       dsaKey.PublicKey.Q.ToBouncyBigInteger(),
                                                                       dsaKey.PublicKey.G.ToBouncyBigInteger()));

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
                                var publicKey = new DsaPublicKeyParameters(dsaKey.Y.ToBouncyBigInteger(),
                                                             new DsaParameters(
                                                                 dsaKey.P.ToBouncyBigInteger(),
                                                                 dsaKey.Q.ToBouncyBigInteger(),
                                                                 dsaKey.G.ToBouncyBigInteger()));
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
            if (String.IsNullOrEmpty(password)){
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
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2202:Do not dispose objects multiple times")]
        public static bool ExportPrimaryAsPkcs(this IKeySet keySet, string location, Func<string> passwordPrompt)
        {
            var i = keySet.Metadata.Versions.First(it => it.Status == KeyStatus.Primary).VersionNumber;
            using (var key = keySet.GetKey(i))
            {
                using (var stream = new FileStream(location, FileMode.Create))
                using (var writer = new StreamWriter(stream))
                {
                    var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(writer);

                    AsymmetricKeyParameter writeKey;
                    if (!(key is IPrivateKey))
                    {
                        if (key.KeyType == KeyType.DsaPub)
                        {
                            var dsaKey = (DsaPublicKey) key;
                            writeKey = new DsaPublicKeyParameters(dsaKey.Y.ToBouncyBigInteger(),
                                                                  new DsaParameters(
                                                                      dsaKey.P.ToBouncyBigInteger(),
                                                                      dsaKey.Q.ToBouncyBigInteger(),
                                                                      dsaKey.G.ToBouncyBigInteger()));
                        }
                        else if (key is IRsaPublicKey)
                        {
                            var rsaKey = (IRsaPublicKey) key;
                            writeKey = new RsaKeyParameters(false,
                                                            rsaKey.Modulus.ToBouncyBigInteger(),
                                                            rsaKey.PublicExponent.ToBouncyBigInteger());
                        }
                        else
                        {
                            throw new InvalidKeyTypeException("Non exportable key type.");
                        }

                        pemWriter.WriteObject(new MiscPemGenerator(writeKey));
                    }
                    else
                    {
                        if (key.KeyType == KeyType.DsaPriv)
                        {
                            var dsaKey = (DsaPrivateKey) key;
                            writeKey = new DsaPrivateKeyParameters(dsaKey.X.ToBouncyBigInteger(),
                                                                   new DsaParameters(
                                                                       dsaKey.PublicKey.P.ToBouncyBigInteger(),
                                                                       dsaKey.PublicKey.Q.ToBouncyBigInteger(),
                                                                       dsaKey.PublicKey.G.ToBouncyBigInteger()));
                        }
                        else if (key is IRsaPrivateKey)
                        {
                            var rsaKey = (IRsaPrivateKey) key;
                            writeKey = new RsaPrivateCrtKeyParameters(
                                rsaKey.PublicKey.Modulus.ToBouncyBigInteger(),
                                rsaKey.PublicKey.PublicExponent.ToBouncyBigInteger(),
                                rsaKey.PrivateExponent.ToBouncyBigInteger(),
                                rsaKey.PrimeP.ToBouncyBigInteger(),
                                rsaKey.PrimeQ.ToBouncyBigInteger(),
                                rsaKey.PrimeExponentP.ToBouncyBigInteger(),
                                rsaKey.PrimeExponentQ.ToBouncyBigInteger(),
                                rsaKey.CrtCoefficient.ToBouncyBigInteger());
                        }
                        else
                        {
                            throw new InvalidKeyTypeException("Non exportable key type.");
                        }

                        pemWriter.WriteObject(new Pkcs8Generator(writeKey, Pkcs8Generator.PbeSha1_RC2_128)
                                                  {
                                                      Password = (passwordPrompt() ?? String.Empty).ToCharArray(),
                                                      SecureRandom = Secure.Random,
                                                      IterationCount = 4096
                                                  });
                    }
                }
            }

            return true;
        }
    }
}