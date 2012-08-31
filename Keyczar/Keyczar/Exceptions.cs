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

namespace Keyczar
{

    /// <summary>
    /// Unoffical Needs Explict Use exception 
    /// </summary>
    public class UnofficalNeedsExplictUseException:Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UnofficalNeedsExplictUseException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public UnofficalNeedsExplictUseException(string message)
            : base(message)
        {

        }
    }


    /// <summary>
    /// Unsupported keyczar version of cipher text or signature exception
    /// </summary>
    public class InvalidCryptoVersionException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoVersionException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidCryptoVersionException(string message)
            : base(message)
        {

        }
    }

    /// <summary>
    /// Invalid Cipher text data or signature exception
    /// </summary>
    public class InvalidCryptoDataException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoDataException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidCryptoDataException(string message):base(message)
        {
           
        }
    }

    /// <summary>
    /// Invalid Key type for usage exception
    /// </summary>
    public class InvalidKeyTypeException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyTypeException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidKeyTypeException(string message)
            : base(message)
        {

        }
    }

    /// <summary>
    /// Invalid keyset exception
    /// </summary>
    public class InvalidKeySetException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeySetException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidKeySetException(string message)
            : base(message)
        {

        }
    }
}