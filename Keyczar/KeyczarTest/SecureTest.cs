/*  Copyright 2013 James Tuley (jay+code@tuley.name)
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyczar.Util;
using NUnit.Framework;

namespace KeyczarTest
{
    [TestFixture]
    public class SecureTest:AssertionHelper
    {
        private byte[] random1;
        private byte[] random2;
        private byte[] randomLarge1;
        private byte[] randomLarge2;
        private byte[] emptyArray;
        [SetUp]
        public void Setup()
        {
            random1 = new byte[32];
            random2 = new byte[32];
            Secure.Random.NextBytes(random1);
            Secure.Random.NextBytes(random2);
            emptyArray = new byte[0];
            randomLarge1 = new byte[96];
            randomLarge2 = new byte[96];
            Secure.Random.NextBytes(randomLarge1);
            Secure.Random.NextBytes(randomLarge2);
        }

        private long AvergateTimeNanoSeconds(Func<bool> comparison, bool expected)
        {  
            var iterations = 500000;
            var timeSpan = new TimeSpan(0);
            for (int i = 0; i < iterations; i++)
            {
                var watch = new System.Diagnostics.Stopwatch();
                watch.Start();
                var actual = comparison();
                watch.Stop();
                timeSpan += watch.Elapsed;
                Expect(actual, Is.EqualTo(expected));
            }
            return (timeSpan.Ticks / iterations) * 100;
        }

        [Test]
        public void TestSecureEqualsEmptyArrayCompare()
        {
           Expect(()=>Secure.Equals(emptyArray, emptyArray),Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void TestSecureEqualsNullArrayCompare()
        {
            Expect(() => Secure.Equals(null, null), Throws.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void TestSecureEqualsMaxCountZero()
        {
            Expect(() => Secure.Equals(randomLarge1, randomLarge2, startIndex:0,maxCount:0), Throws.TypeOf<ArgumentOutOfRangeException>());
        }


        [Test]
        public void TestSecureEqualsAttemptToSkipLoop()
        {
            Expect(() => Secure.Equals(randomLarge1, randomLarge2, startIndex: -32, maxCount: 32), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        private void ExpectAverageTimeDifferencesSafe(long avg1NanoSeconds, long avg2NanoSeconds)
        {
            //if the entire difference of operation is less than 200 nano seconds
            //and 200 nano seconds is the narrowest event that can be detected over a lan within an operation 
            //then we can be reasonably assume that any comparision differences are not detectable.
            //but different runtimes, cpu's etc can effect this, we can only do our best in such situations.
            Expect(Math.Abs(avg1NanoSeconds - avg2NanoSeconds), Is.LessThan(200));
        }

        [Test]
        public void TestSecureEqualsSameLengthConstantTimeCompareTests()
        {
           var avgCompare1 = AvergateTimeNanoSeconds(() => Secure.Equals(random1, random1), true);
           var avgCompare2 = AvergateTimeNanoSeconds(() => Secure.Equals(random1, random2), false);
            ExpectAverageTimeDifferencesSafe(avgCompare1, avgCompare2);
        }

        [Test]
        public void TestSecureEqualsSameLengthConstantTimeCompareTestsLarge()
        {
            var avgCompare1 = AvergateTimeNanoSeconds(() => Secure.Equals(randomLarge1, randomLarge1, startIndex: 32, maxCount: 32), true);
            var avgCompare2 = AvergateTimeNanoSeconds(() => Secure.Equals(randomLarge1, randomLarge2, startIndex: 32, maxCount: 32), false);
            ExpectAverageTimeDifferencesSafe(avgCompare1, avgCompare2);
        }

        [Test]
        public void TestSecureEqualsDifferentLengthConstantTimeCompareTestsLarge()
        {
            var avgCompare1 = AvergateTimeNanoSeconds(() => Secure.Equals(randomLarge1, randomLarge1, startIndex: 32, maxCount: 32), true);
            var avgCompare2 = AvergateTimeNanoSeconds(() => Secure.Equals(emptyArray, randomLarge1, startIndex: 32, maxCount: 32), false);
            ExpectAverageTimeDifferencesSafe(avgCompare1, avgCompare2);
        }

        [Test]
        public void TestSecureEqualsDifferentLengthConstantTimeCompareTests()
        {
            var avgCompare1 = AvergateTimeNanoSeconds(() => Secure.Equals(random1, random1), true);
            var avgCompare2 = AvergateTimeNanoSeconds(() => Secure.Equals(emptyArray, random2), false);
            ExpectAverageTimeDifferencesSafe(avgCompare1, avgCompare2);
        }


        [Test]
        public void TestSecureEqualsDifferentLengthConstantTimeCompareTests2()
        {
            var avgCompare1 = AvergateTimeNanoSeconds(() => Secure.Equals(random1, random1), true);
            var avgCompare2 = AvergateTimeNanoSeconds(() => Secure.Equals(random1, emptyArray), false);
            ExpectAverageTimeDifferencesSafe(avgCompare1, avgCompare2);
        }


    
    }
}
