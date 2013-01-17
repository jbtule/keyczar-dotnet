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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace Keyczar.Util
{
    /// <summary>
    /// Useful security utilties
    /// </summary>
    public static class Secure
    {
        /// <summary>
        /// Random byte generator
        /// </summary>
        public static readonly SecureRandom Random = new SecureRandom();


        /// <summary>
        /// Disposes if not null and returns null to empty variables in one line
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="disposable">The disposable.</param>
        /// <returns></returns>
        public static T SafeDispose<T>(this T disposable) where T:class,IDisposable
        {
            if(disposable != null)
                disposable.Dispose();
            return null;
        }


        /// <summary>
        /// Runs the action if the target is not null or the default action if it is null.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <typeparam name="TReturn"></typeparam>
        /// <param name="target">The target.</param>
        /// <param name="action">The action.</param>
        /// <param name="defaultAction">The default action.</param>
        /// <returns></returns>
        public static TReturn Maybe<T, TReturn>(this T target, Func<T, TReturn> action, Func<TReturn> defaultAction) where T : class
        {
            if (target != null)
            {
                return action(target);
            }
            return defaultAction();
        }


        /// <summary>
        /// Clears the specified array.
        /// </summary>
        /// <param name="a">A.</param>
        public static T[] Clear<T>(this T[] a)
        {
            if (a != null)
                Array.Clear(a, 0, a.Length);
            return null;
        }



        /// <summary>
        /// The _dummy array for fake comparison that will return false
        /// </summary>
        private static readonly byte[] DummyArray = new byte[] { 1, 2 };
        /// <summary>
        /// Compares the arrays in a conservative way.
        /// </summary>
        /// <param name="a">Array A.</param>
        /// <param name="b">Array b.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static bool Equals(Array a, Array b, int startIndex =0)
        {
            //We don't ever want to use this function to compare two nulls
            //so conservatively returning false;
            if(a== null && b == null)
                return false;

            if (a == null)
                a = new object[] {};
            if (b == null)
                b = new object[] { };
            var length = Math.Max(a.Length, b.Length);

            var compare = true;
            
            //We don't ever want to use this function to compare zero length arrays
            //so conservatively returning false;
            if(length ==0)
                return false;

            //we compare every index even when we know the result is false
            for (var i = 0; i < length; i++)
            {
                if(i < startIndex)
                    continue;

                //This first case is used to try and not leak when a key matching a keyhash couldn't be found.
                if (a.GetLength(0) <= i | b.GetLength(0) <= i) //uses non short ciruit "or (|)"
                    //always returns false
                    compare = DummyArray.GetValue(0).Equals(DummyArray.GetValue(1)) & compare;  //uses non short ciruit "and (&)"
                else
                    compare = a.GetValue(i).Equals(b.GetValue(i)) & compare; //uses non short ciruit "and (&)"
            }
            return compare;
        }
    }
}
