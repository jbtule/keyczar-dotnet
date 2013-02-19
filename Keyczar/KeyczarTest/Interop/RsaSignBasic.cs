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

namespace KeyczarTest.Interop
{
    [TestFixture]
    public class RsaSignBasic : PublicVerifierBasicInterop
    {
        public RsaSignBasic(string imp) : base(imp)
        {
            Location = "rsa-sign";
        }

        [TestCase("1024")]
        [TestCase("2048")]
        [TestCase("4096")]
        public void VerifyVariousSizes(string size)
        {
            HelperVerifyVariousSizes(size);
        }

        [TestCase("1024")]
        [TestCase("2048")]
        [TestCase("4096")]
        public void PublicVerifyVariousSizes(string size)
        {
            HelperPublicVerifyVariousSizes(size);
        }
    }
}