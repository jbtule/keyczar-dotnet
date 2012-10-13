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
	[TestFixture][Category("Performance")]
	public class PerfTest:AssertionHelper
	{
        /// <summary>
        /// Custom KeyType AES decryption using bouncy castle.
        /// </summary>
	    public static KeyType BOUNCY_AES = null;

        [SetUp]
        public void Setup()
        {
            if (BOUNCY_AES == null)
            {
                BOUNCY_AES = KeyType.Name("BOUNCY_AES").KeySizes<BouncyAESKey>(128, 192, 256).DefineSpec();
            }
        }

		public const int iterations = 10000;

		[Test]
		public void AESTest(
			[Values(2048)]int datasize,
			[Values(128,192,256)]int keysize,
			[Values("AES", "BOUNCY_AES", "C#_AES_AEAD")]string alg 
			)
		{
			KeyType type = alg;
			var key =Key.Generate(type,keysize);
			using(var ks = new ImportedKeySet(key,KeyPurpose.DECRYPT_AND_ENCRYPT,"Test"))
			using(var crypter = new Crypter(ks))
			{
				var watchEncrypt = new System.Diagnostics.Stopwatch();
				var watchDecrypt = new System.Diagnostics.Stopwatch();
				for(int i=0; i < iterations; i++){
					var input = new byte[datasize];
				
					watchEncrypt.Start();
					var output =crypter.Encrypt(input);
					watchEncrypt.Stop();

					watchDecrypt.Start();
					var result =crypter.Decrypt(output);
					watchDecrypt.Stop();

					Expect(result, Is.EqualTo(input));
				}

				Console.WriteLine(String.Format("{3}-{4},{2}\t\tEncryption Total:{0},\tThroughput:{1:#,##0.00} MB/S", 
				                                watchEncrypt.Elapsed,
				                                (datasize * iterations * 1000m) / (1024m * 1024m * watchEncrypt.ElapsedMilliseconds), 
				                                datasize,
				                                alg,
				                                keysize
				                                ));
				Console.WriteLine(String.Format("{3}-{4},{2}\t\tDecryption Total:{0},\tThroughput:{1:#,##0.00} MB/S",
				                                watchDecrypt.Elapsed,
				                                (datasize * iterations * 1000m) / (1024m * 1024m * watchDecrypt.ElapsedMilliseconds), 
				                                datasize,
				                                alg,
				                                keysize
				                                ));

			}
		}
	}

	public class BouncyAESKey:Keyczar.Crypto.AesKey{
	

		/// <summary>
		/// Gets the encrypting stream.
		/// </summary>
		/// <param name="output">The output.</param>
		/// <returns></returns>
		public override FinishingStream GetEncryptingStream(Stream output)
		{

			 var ivarr = new byte[BlockLength];
			 Random.NextBytes(ivarr);
			 return new SymmetricStream(
			 new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
			 output,
			 ivarr,
			 HmacKey.HashLength,
			 (iv, cipher, encrypt) => cipher.Init(forEncryption: encrypt, parameters: new ParametersWithIV(new KeyParameter(AesKeyBytes), iv)),
			 encrypt: true);
			
		}
		
		/// <summary>
		/// Gets the decrypting stream.
		/// </summary>
		/// <param name="output">The output.</param>
		/// <returns></returns>
		public override FinishingStream GetDecryptingStream(Stream output)
		{

			return new SymmetricStream(
			     new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
			     output, 
			     new byte[BlockLength],
			     HmacKey.HashLength,
			     (iv, cipher, encrypt) => cipher.Init(forEncryption: encrypt, parameters: new ParametersWithIV(new KeyParameter(AesKeyBytes), iv)),
			     encrypt:false);
		}
	}
}

