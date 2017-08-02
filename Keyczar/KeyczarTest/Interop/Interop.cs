/*  
 *  Copyright 2013 James Tuley (jay+code@tuley.name)
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
using NUnit.Framework;
using System.IO;

namespace KeyczarTest.Interop
{
    [Category("Iterop")]
    public abstract class BasicInterop : Interop
    {
        public BasicInterop(string implementation) : base(implementation)
        {
        }
    }
   
    [TestFixture("py3")]
    [TestFixture("cs")]
    [TestFixture("py")]
    [TestFixture("j")]
    [TestFixture("go")]
    public abstract class Interop : AssertionHelper
    {
        private string _implementation;

        public String Input
        {
            get { return "This is some test data"; }
        }


        public Interop(string implementation)
        {
            _implementation = implementation;
        }

        public string TestData(string dir)
        {
            return Util.TestDataPath(Path.Combine("remote-testdata", "interop-data", _implementation + "_data"), dir);
        }
    }
}
