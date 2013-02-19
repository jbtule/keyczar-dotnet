using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Util;
using NUnit.Framework;


namespace KeyczarTest{

   
   [TestFixture("rem|dotnet")]
   [TestFixture("gen|cstestdata")]
   [TestFixture("gen|tool_cstestdata")]
   public class StreamBehaviorTest:AssertionHelper
    {    
       
       private readonly String TEST_DATA;

        public StreamBehaviorTest(string testPath)
          {
			testPath =Util.ReplaceDirPrefix(testPath);

              TEST_DATA = testPath;
          }


        private static String input = "This is some test data";
       private const int ExtraDataLength = 10;

       protected Stream InputStream
       {
           get { return new MemoryStream(Encoding.UTF8.GetBytes(input)); }
       }

       [Test]
       public void TestEncryptDecryptStream(
           [Values("aes", "rsa", "aes_aead")] String subDir,
           [Values(CompressionType.None, CompressionType.Gzip, CompressionType.Zlib)] CompressionType type)
       {
           string nestedDir = "";
           if (subDir == "aes_aead")
               nestedDir = "unofficial";

           var subPath = Util.TestDataPath(TEST_DATA, subDir, nestedDir);

           using (var crypter = new Crypter(subPath))
           {
               crypter.Compression = type;
               var streamOutput = new MemoryStream();
               streamOutput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               long encryptedLength;
               using (Utility.ResetStreamWhenFinished(streamOutput))
               {
                   var position = streamOutput.Position;
                   crypter.Encrypt(InputStream, streamOutput);
                   encryptedLength = streamOutput.Length - position;
                   streamOutput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               }
               Expect(streamOutput.Position, Is.EqualTo(ExtraDataLength));
               var streamDecrypt = new MemoryStream();
               crypter.Decrypt(streamOutput, streamDecrypt, encryptedLength);
               Expect(Encoding.UTF8.GetString(streamDecrypt.ToArray()),Is.EqualTo(input));
               Expect(streamOutput.Position, Is.EqualTo(encryptedLength + ExtraDataLength));
               
           }
       }

       [TestCase("hmac")]
       [TestCase("dsa")]
       [TestCase("rsa-sign")]
       public void TestSignAndVerify(String subDir)
       {
           var subPath = Util.TestDataPath(TEST_DATA, subDir);
           using (var signer = new Signer(subPath))
           {
               var streamInput = new MemoryStream();
               streamInput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               using (Utility.ResetStreamWhenFinished(streamInput))
               {
                   InputStream.CopyTo(streamInput);
                   streamInput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               }

               Expect(streamInput.Position, Is.EqualTo(ExtraDataLength));
               byte[] sig;
               using(Utility.ResetStreamWhenFinished(streamInput))
                   sig = signer.Sign(streamInput, InputStream.Length);
               Expect(streamInput.Position, Is.EqualTo(10));
               Expect(signer.Verify(streamInput, sig, InputStream.Length), Is.True);
               Expect(streamInput.Position, Is.EqualTo(InputStream.Length + ExtraDataLength));
           }
       }

       [TestCase("hmac")]
       [TestCase("dsa")]
       [TestCase("rsa-sign")]
       public void TestTimeoutSignAndVerify(string subPath)
       {

           using (var signer = new TimeoutSigner(Util.TestDataPath(TEST_DATA, subPath)))
           {
               var streamInput = new MemoryStream();
               streamInput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               using (Utility.ResetStreamWhenFinished(streamInput))
               {
                   InputStream.CopyTo(streamInput);
                   streamInput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               }

               Expect(streamInput.Position, Is.EqualTo(ExtraDataLength));
               byte[] sig;
               // Create a signature that will be valid for a long time
               using (Utility.ResetStreamWhenFinished(streamInput))
                   sig = signer.Sign(streamInput, DateTime.Now.AddDays(365), InputStream.Length);
               Expect(streamInput.Position, Is.EqualTo(ExtraDataLength));
               Expect(signer.Verify(streamInput, sig, InputStream.Length), Is.True);
               Expect(streamInput.Position, Is.EqualTo(InputStream.Length + ExtraDataLength));
           }
       }

       [TestCase("hmac")]
       [TestCase("dsa")]
       [TestCase("rsa-sign")]
       public void TestVanillaSignAndVerify(String subDir)
       {
           using (var signer = new VanillaSigner(Util.TestDataPath(TEST_DATA, subDir)))
           {
               var streamInput = new MemoryStream();
               streamInput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               using (Utility.ResetStreamWhenFinished(streamInput))
               {
                   InputStream.CopyTo(streamInput);
                   streamInput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               }

               Expect(streamInput.Position, Is.EqualTo(ExtraDataLength));
               byte[] sig;
               // Create a signature that will be valid for a long time
               using (Utility.ResetStreamWhenFinished(streamInput))
                   sig = signer.Sign(streamInput, InputStream.Length);
               Expect(streamInput.Position, Is.EqualTo(ExtraDataLength));
               Expect(signer.Verify(streamInput, sig, InputStream.Length), Is.True);
               Expect(streamInput.Position, Is.EqualTo(InputStream.Length + ExtraDataLength));
      
           }
       }

       [TestCase("hmac")]
       [TestCase("dsa")]
       [TestCase("rsa-sign")]
       public void TestSignAndVerifyMessage(String subDir)
       {
           var subPath = Util.TestDataPath(TEST_DATA, subDir);
           using (var signer = new AttachedSigner(subPath))
           {
               var streamOutput = new MemoryStream();
               streamOutput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               long signedLength;
               using (Utility.ResetStreamWhenFinished(streamOutput))
               {
                   var position = streamOutput.Position;
                   signer.Sign(InputStream, streamOutput);
                   signedLength = streamOutput.Length - position;
                   streamOutput.Write(new byte[ExtraDataLength], 0, ExtraDataLength);
               }
               Expect(streamOutput.Position, Is.EqualTo(10));
               var streamMessage = new MemoryStream();
               signer.VerifiedMessage(streamOutput, streamMessage, inputLength: signedLength);

               Expect(Encoding.UTF8.GetString(streamMessage.ToArray()), Is.EqualTo(input));
               Expect(streamOutput.Position, Is.EqualTo(signedLength + ExtraDataLength));

           }
       }

    }
}
