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
using NUnit.Framework;
using Keyczar;
using System.IO;
using System.Linq;

namespace KeyczarTest.Interop
{
    [TestFixture("py3")]
    [TestFixture("cs")]
    [TestFixture("py")]
    [TestFixture("j")]
    [TestFixture("go")]
    public class Aes : CrypterBasicInterop
    {
        public Aes(string imp) : base(imp)
        {
            Location = "aes";
        }  

        [TestCase("128")]
        [TestCase("192")]
        [TestCase("256")]
        public void DecryptVariousSizes(string size)
        {
            HelperDecryptVariousSizes(size);
        }
    }
}