/*  Copyright 2012 James Tuley (jay+code@tuley.name)
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

using System;
using System.Security.Cryptography;
using Keyczar.Util;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Paddings;
using NUnit.Framework;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Crypto.Streams;
using System.IO;

namespace KeyczarTest
{
    [TestFixture]
    [Category("Performance")]
    public class PerfTest : AssertionHelper
    {
        /// <summary>
        /// Custom KeyType AES decryption using bouncy castle.
        /// </summary>
        public static KeyType STDNET40_AES = null;

        [SetUp]
        public void Setup()
        {
            if (STDNET40_AES == null)
            {
                STDNET40_AES = KeyType.Name("STDNET40_AES").KeySizes<StdNET40AESKey>(128, 192, 256).DefineSpec();
            }
        }

        public const int iterations = 10000;

        [Test]
        public void AESTest(
            [Values(2048)] int datasize,
            [Values(128, 192, 256)] int keysize,
            [Values("AES", "STDNET40_AES", "C#_AES_AEAD")] string alg
            )
        {
            KeyType type = alg;
            var key = Key.Generate(type, keysize);
            using (var ks = new ImportedKeySet(key, KeyPurpose.DecryptAndEncrypt, "Test"))
            using (var crypter = new Crypter(ks))
            {
                var watchEncrypt = new System.Diagnostics.Stopwatch();
                var watchDecrypt = new System.Diagnostics.Stopwatch();
                for (int i = 0; i < iterations; i++)
                {
                    var input = new byte[datasize];

                    watchEncrypt.Start();
                    var output = crypter.Encrypt(input);
                    watchEncrypt.Stop();

                    watchDecrypt.Start();
                    var result = crypter.Decrypt(output);
                    watchDecrypt.Stop();

                    Expect(result, Is.EqualTo(input));
                }

                Console.WriteLine(String.Format("{3}-{4},{2}\t\tEncryption Total:{0},\tThroughput:{1:#,##0.00} MB/S",
                                                watchEncrypt.Elapsed,
                                                (datasize*iterations*1000m)/
                                                (1024m*1024m*watchEncrypt.ElapsedMilliseconds),
                                                datasize,
                                                alg,
                                                keysize
                                      ));
                Console.WriteLine(String.Format("{3}-{4},{2}\t\tDecryption Total:{0},\tThroughput:{1:#,##0.00} MB/S",
                                                watchDecrypt.Elapsed,
                                                (datasize*iterations*1000m)/
                                                (1024m*1024m*watchDecrypt.ElapsedMilliseconds),
                                                datasize,
                                                alg,
                                                keysize
                                      ));
            }
        }
    }

    public class StdNET40AESKey : Keyczar.Crypto.AesKey
    {
        /// <summary>
        /// Gets the mode.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidKeyTypeException">Unsupport AES Mode: </exception>
        private CipherMode GetMode()
        {
            if (Mode == "CBC")
            {
                return CipherMode.CBC;
            }
            throw new InvalidKeyTypeException("Unsupported AES Mode: " + Mode);
        }

        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public override FinishingStream GetEncryptingStream(Stream output)
        {
            var alg = new AesManaged
                          {
                              Mode = GetMode(),
                              Key = AesKeyBytes,
                              Padding = PaddingMode.PKCS7,
                              BlockSize = BlockLength*8
                          };
            alg.GenerateIV();


            int hashlength = HmacKey.Maybe(h => h.HashLength, () => 0);
            return new DotNetSymmetricStream(alg, output, hashlength, encrypt: true);
        }

        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public override FinishingStream GetDecryptingStream(Stream output)
        {
            var alg = new AesManaged
                          {
                              Mode = GetMode(),
                              Key = AesKeyBytes,
                              Padding = PaddingMode.PKCS7,
                              BlockSize = BlockLength*8
                          };
            return new DotNetSymmetricStream(alg, output, HmacKey.Maybe(h => h.HashLength, () => 0), encrypt: false);
        }
    }
}