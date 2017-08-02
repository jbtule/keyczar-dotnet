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
using System.Runtime.Serialization;

namespace Keyczar
{
    /// <summary>
    /// Unoffical Needs Explict Use exception 
    /// </summary>
    [Serializable]
    public class UnofficialNeedsExplicitUseException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UnofficialNeedsExplicitUseException" /> class.
        /// </summary>
        public UnofficialNeedsExplicitUseException() : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UnofficialNeedsExplicitUseException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public UnofficialNeedsExplicitUseException(string message)
            : base(message)
        {
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="UnofficialNeedsExplicitUseException" /> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public UnofficialNeedsExplicitUseException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UnofficialNeedsExplicitUseException" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected UnofficialNeedsExplicitUseException(SerializationInfo info,
                                                      StreamingContext context) : base(info, context)
        {
        }
    }


    /// <summary>
    /// Unsupported keyczar version of cipher text or signature exception
    /// </summary>
    [Serializable]
    public class InvalidCryptoVersionException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoVersionException" /> class.
        /// </summary>
        public InvalidCryptoVersionException() : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoVersionException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidCryptoVersionException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoVersionException" /> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public InvalidCryptoVersionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoVersionException" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected InvalidCryptoVersionException(SerializationInfo info,
                                                StreamingContext context) : base(info, context)
        {
        }
    }

    /// <summary>
    /// Invalid Cipher text data or signature exception
    /// </summary>
    [Serializable]
    public class InvalidCryptoDataException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoDataException" /> class.
        /// </summary>
        public InvalidCryptoDataException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoDataException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidCryptoDataException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoDataException" /> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public InvalidCryptoDataException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidCryptoDataException" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected InvalidCryptoDataException(SerializationInfo info,
                                             StreamingContext context) : base(info, context)
        {
        }
    }

    /// <summary>
    /// Invalid Key type for usage exception
    /// </summary>
    [Serializable]
    public class InvalidKeyTypeException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyTypeException" /> class.
        /// </summary>
        public InvalidKeyTypeException()
            : base()
        {
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyTypeException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidKeyTypeException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyTypeException" /> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public InvalidKeyTypeException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyTypeException" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected InvalidKeyTypeException(SerializationInfo info,
                                          StreamingContext context) : base(info, context)
        {
        }
    }

    /// <summary>
    /// Invalid keyset exception
    /// </summary>
    [Serializable]
    public class InvalidKeySetException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeySetException" /> class.
        /// </summary>
        public InvalidKeySetException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeySetException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        public InvalidKeySetException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeySetException" /> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public InvalidKeySetException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeySetException" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected InvalidKeySetException(SerializationInfo info,
                                         StreamingContext context) : base(info, context)
        {
        }
    }
}