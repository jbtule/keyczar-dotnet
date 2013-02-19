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
using System.IO;
using Keyczar.Crypto.Streams;

namespace Keyczar.Crypto
{
    /// <summary>
    /// Interface for all keys
    /// </summary>
    public interface IKey
    {
        /// <summary>
        /// Gets the key hash.
        /// </summary>
        /// <returns></returns>
        byte[] GetKeyHash();

        /// <summary>
        /// Gets the fallback key hash.
        /// </summary>
        /// <returns></returns>
        IEnumerable<byte[]> GetFallbackKeyHash();
    }

    /// <summary>
    ///  Interface for keys that can be use for PBE encryption of keys
    /// </summary>
    internal interface IPbeKey
    {
    }

    /// <summary>
    /// interfaces for keys that can be used for signing &amp; verifying
    /// </summary>
    public interface ISignerKey : IVerifierKey
    {
        /// <summary>
        /// Gets the signing stream.
        /// </summary>
        /// <returns></returns>
        HashingStream GetSigningStream();
    }

    /// <summary>
    /// Interface for keys that can be used for verifying
    /// </summary>
    public interface IVerifierKey : IKey
    {
        /// <summary>
        /// Gets the verifying stream.
        /// </summary>
        /// <returns></returns>
        VerifyingStream GetVerifyingStream();
    }

    /// <summary>
    /// interface for keys that can be used for encrypting
    /// </summary>
    public interface IEncrypterKey : IKey
    {
        /// <summary>
        /// Gets the encrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        FinishingStream GetEncryptingStream(Stream output);

        /// <summary>
        /// Gets the authentication signing stream.
        /// </summary>
        /// <returns></returns>
        HashingStream GetAuthSigningStream();
    }

    /// <summary>
    /// interface for keys that can be used for encrypting or decrypting
    /// </summary>
    public interface ICrypterKey : IEncrypterKey
    {
        /// <summary>
        /// Gets the decrypting stream.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        FinishingStream GetDecryptingStream(Stream output);

        /// <summary>
        /// Gets the authentication verifying stream.
        /// </summary>
        /// <returns></returns>
        VerifyingStream GetAuthVerifyingStream();
    }

    /// <summary>
    /// interface for private key of public/private key encryption
    /// </summary>
    public interface IPrivateKey
    {
        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <value>The public key.</value>
        Key PublicKey { get; }
    }
}