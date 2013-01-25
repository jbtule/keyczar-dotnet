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
using System.Linq;
using System.Numerics;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Serialization;
using Org.BouncyCastle.Crypto.Digests;

namespace Keyczar.Util
{
    /// <summary>
    /// Utility methods
    /// </summary>
    public static class Utility
    {
        /// <summary>
        /// Resets the stream poisition when Closed or Disposed.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns></returns>
        public static NondestructiveStreamReset ResetStreamWhenFinished(Stream stream)
        {
            return new NondestructiveStreamReset(stream);
        }

        /// <summary>
        /// Copies string/object dictionary to the destnation objects properties.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="destination">The dest.</param>
        public static void CopyProperties(IDictionary<string,object> source, object destination)
        {
            foreach (var pair in source)
            {
                var prop =destination.GetType().GetProperty(pair.Key);
                if (prop != null)
                {
                    prop.SetValue(destination,pair.Value,null);
                }
            }
        }

        /// <summary>
        /// Copies the properties from one object to the next
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="destination">The dest.</param>
        public static void CopyProperties(object source, object destination)
        {
            var dict =source.GetType().GetProperties().ToDictionary(k => k.Name, v => v.GetValue(source,null));
            CopyProperties(dict, destination);
        }


        /// <summary>
        /// Json Serializes the object.
        /// </summary>
        /// <param name="value">The obj.</param>
        /// <returns></returns>
        public static string ToJson(this object value)
        {
            return JsonConvert.SerializeObject(value,
                new JsonSerializerSettings {ContractResolver = new CamelCasePropertyNamesContractResolver()});
        }


        /// <summary>
        /// Bson Serializes the object.
        /// </summary>
        /// <param name="value">The obj.</param>
        /// <returns></returns>
        public static byte[] ToBson(this object value)
        {
            using (var output = new MemoryStream())
            {
                var serializer = new JsonSerializer {ContractResolver = new CamelCasePropertyNamesContractResolver(), };
                var writer = new BsonWriter(output);
                serializer.Serialize(writer, value);
                output.Flush();
                return output.ToArray();
            }
        }

        /// <summary>
        /// To the system standard big integer.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
		public static BigInteger ToSystemBigInteger(this Org.BouncyCastle.Math.BigInteger value){
			var bytes = value.ToByteArray();
			if(BitConverter.IsLittleEndian){
				Array.Reverse(bytes);
			}
			var bigint = new BigInteger(bytes);
			return bigint;
		}

        /// <summary>
        /// To the bouncy castle big integer.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
		public static Org.BouncyCastle.Math.BigInteger ToBouncyBigInteger(this BigInteger value){
			var bytes = Utility.GetBytes(value);
			var bigint = new Org.BouncyCastle.Math.BigInteger(bytes);
			return bigint;
		}

        /// <summary>
        /// Gets the bytes for an int laid out big endian
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public static byte[] GetBytes(int data)
        {
            var bytes = BitConverter.GetBytes(data);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

        /// <summary>
        /// Gets the bytes for a long laid out big endian
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public static byte[] GetBytes(long data)
        {
            var bytes = BitConverter.GetBytes(data);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

		/// <summary>
		/// Gets the bytes for a long laid out big endian
		/// </summary>
		/// <param name="data">The data.</param>
		/// <returns></returns>
		public static byte[] GetBytes(BigInteger data){
			var bytes = data.ToByteArray();
			if(BitConverter.IsLittleEndian){
				Array.Reverse(bytes);
			}
			return bytes;
		}

		/// <summary>
		/// To the BigInteger from big endian bytes.
		/// </summary>
		/// <param name="data">The data.</param>
		/// <returns></returns>
		public static BigInteger ToBigInteger(byte[] data)
		{
			var dataclone = (byte[]) data.Clone();
			if (BitConverter.IsLittleEndian)
			{
				Array.Reverse(dataclone);
			}
			return new BigInteger(dataclone);
		}

        /// <summary>
        /// To the int64 from big endian bytes.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public static long ToInt64(byte[] data)
        {
			var dataclone = (byte[]) data.Clone();
            if (BitConverter.IsLittleEndian)
            {
				Array.Reverse(dataclone);
            }
			return BitConverter.ToInt64(dataclone,0);
        }

        /// <summary>
        /// To the int32 from big endian bytes.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public static int ToInt32(byte[] data)
        {
			var dataclone = (byte[]) data.Clone();
            if (BitConverter.IsLittleEndian)
            {
				Array.Reverse(dataclone);
            }
			return BitConverter.ToInt32(dataclone, 0);
        }

        /// <summary>
        /// Reads the keyczar header.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="keyHash">The key hash.</param>
        /// <returns></returns>
        public static byte[] ReadHeader(byte[] data, out byte[] keyHash)
        {
            var output = new byte[Keyczar.HeaderLength];
            
            Array.Copy(data, 0, output, 0, output.Length);
            keyHash = new byte[Keyczar.KeyHashLength];
            Array.Copy(data, Keyczar.FormatBytes.Length, keyHash, 0, keyHash.Length);

            if(output[0] !=  Keyczar.FormatVersion)
                 throw new InvalidCryptoVersionException("The version identifier doesn't match the current framework.");

            return output;
        }

        /// <summary>
        ///  Reads the keyczar header.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="keyHash">The key hash.</param>
        /// <returns></returns>
        public static byte[] ReadHeader(Stream data, out byte[] keyHash)
        {
            var output = new byte[Keyczar.HeaderLength];
            data.Read(output, 0, output.Length);
            keyHash = new byte[Keyczar.KeyHashLength];
            Array.Copy(output, Keyczar.FormatBytes.Length, keyHash, 0, keyHash.Length);
            return output;
        }

        /// <summary>
        /// Hashes the key for keyczar version look ups.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <param name="components">The components.</param>
        /// <returns></returns>
        public static byte[] HashKey(int size, params byte[][] components)
        {
           var sha1 = new Sha1Digest();
            
           foreach (var data in components)
           {
               sha1.BlockUpdate(data,0, data.Length);
           }

           var hash = new byte[sha1.GetDigestSize()];
           sha1.DoFinal(hash, 0);
           sha1.Reset();
           var outBytes = new byte[size];
           Array.Copy(hash, 0, outBytes, 0, outBytes.Length);
           return outBytes;
        }

        /// <summary>
        /// Hashes each component of the key hash with it's length first.
        /// </summary>
        /// <param name="size">The size.</param>
        /// <param name="components">The components.</param>
        /// <returns></returns>
        public static byte[] HashKeyLengthPrefix(int size, params byte[][] components)
        {
             var sha1 = new Sha1Digest();
            
            foreach (var data in components)
            {
                byte[] length = GetBytes(data.Length);
                sha1.BlockUpdate(length,0, length.Length);
                sha1.BlockUpdate(data,0, data.Length);
            }
            var hash = new byte[sha1.GetDigestSize()];
            sha1.DoFinal(hash, 0);
            sha1.Reset();
            var outBytes = new byte[size];
            Array.Copy(hash, 0, outBytes, 0, outBytes.Length);
            return outBytes;
        }


        /// <summary>
        /// Strips the leading zeros from a byte array.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public static byte[] StripLeadingZeros(byte[] data)
        {
            var index = Array.FindIndex(data, it => it != 0);
            index = Math.Max(index, 0);
            var output = new byte[data.Length - index];
            Array.Copy(data, index, output, 0, output.Length);
            return output;
        }

    }
}
