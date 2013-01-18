//
//  Copyright 2013  
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyczar;
using NUnit.Framework;

namespace KeyczarTest.Interop
{
    [TestFixture]
    public class AesCrypted : Interop
    {
        public AesCrypted(string implementation) : base(implementation)
        {
        }

        [Test]
        public void Decrypt()
        {
            var keyPath = TestData("aes");
            var dataPath = TestData("aes-crypted");

            var activeCiphertext = (WebBase64)File.ReadAllLines(Path.Combine(dataPath, "1.out")).First();
            var primaryCiphertext = (WebBase64)File.ReadAllLines(Path.Combine(dataPath, "2.out")).First();
            using (var keyDecrypter = new Crypter(keyPath))
            using (var crypter = new Crypter(new EncryptedKeySet(dataPath, keyDecrypter)))
            {
                var activeDecrypted = crypter.Decrypt(activeCiphertext);
                Expect(activeDecrypted, Is.EqualTo(Input));
                var primaryDecrypted = crypter.Decrypt(primaryCiphertext);
                Expect(primaryDecrypted, Is.EqualTo(Input));
            }
        }
    }
}
