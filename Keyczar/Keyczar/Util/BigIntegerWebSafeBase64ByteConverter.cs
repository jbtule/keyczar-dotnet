/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * A web-safe Base64 encoding and decoding utility class. See RFC 3548
 *
 * @author steveweis@gmail.com (Steve Weis)
 * 
 * 
 * 8/2012 Directly ported to C# and added JsonConverter - jay+code@tuley.name (James Tuley)
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using System.Numerics;

namespace Keyczar.Util
{
	/// <summary>
	/// Encodes byte arrays to websafe base64 in json and vice versa
	/// </summary>
	public class BigIntegerWebSafeBase64ByteConverter:WebSafeBase64ByteConverter
	{
		/// <summary>
		/// Writes the JSON representation of the object.
		/// </summary>
		/// <param name="writer">The <see cref="T:Newtonsoft.Json.JsonWriter"/> to write to.</param>
		/// <param name="value">The value.</param>
		/// <param name="serializer">The calling serializer.</param>
		public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
		{
			base.WriteJson(writer,Utility.GetBytes((BigInteger)value),serializer);
		}
		
		/// <summary>
		/// Reads the JSON representation of the object.
		/// </summary>
		/// <param name="reader">The <see cref="T:Newtonsoft.Json.JsonReader"/> to read from.</param>
		/// <param name="objectType">Type of the object.</param>
		/// <param name="existingValue">The existing value of object being read.</param>
		/// <param name="serializer">The calling serializer.</param>
		/// <returns>The object value.</returns>
		public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
		{

			var value = (byte[])base.ReadJson(reader,objectType,existingValue,serializer);

			var final = Utility.ToBigInteger(value);
			Secure.Clear(value);
			return final;
		}
		
		/// <summary>
		/// Determines whether this instance can convert the specified object type.
		/// </summary>
		/// <param name="objectType">Type of the object.</param>
		/// <returns>
		/// 	<c>true</c> if this instance can convert the specified object type; otherwise, <c>false</c>.
		/// </returns>
		public override bool CanConvert(Type objectType)
		{
			return objectType == typeof (BigInteger);
		}
	}



    /// <summary>
    /// Encodes byte arrays to websafe base64 in json and vice versa
    /// </summary>
    public class WebSafeBase64ByteConverter:JsonConverter
    {
        /// <summary>
        /// Writes the JSON representation of the object.
        /// </summary>
        /// <param name="writer">The <see cref="T:Newtonsoft.Json.JsonWriter"/> to write to.</param>
        /// <param name="value">The value.</param>
        /// <param name="serializer">The calling serializer.</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (writer is BsonWriter)
            {
                serializer.Serialize(writer, value);
            }
            else
            {

                var encoded = WebSafeBase64.Encode(((byte[]) value));
                serializer.Serialize(writer, new string(encoded));
                Secure.Clear(encoded);
            }
        }

        /// <summary>
        /// Reads the JSON representation of the object.
        /// </summary>
        /// <param name="reader">The <see cref="T:Newtonsoft.Json.JsonReader"/> to read from.</param>
        /// <param name="objectType">Type of the object.</param>
        /// <param name="existingValue">The existing value of object being read.</param>
        /// <param name="serializer">The calling serializer.</param>
        /// <returns>The object value.</returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            byte[] final;
            if (reader is BsonReader)
            {
                final = serializer.Deserialize<byte[]>(reader);
            }
            else
            {
                var base64 = (serializer.Deserialize<string>(reader) ?? String.Empty).ToCharArray();
                final = WebSafeBase64.Decode(base64);
                Secure.Clear(base64);

            }
            return final;
        }

        /// <summary>
        /// Determines whether this instance can convert the specified object type.
        /// </summary>
        /// <param name="objectType">Type of the object.</param>
        /// <returns>
        /// 	<c>true</c> if this instance can convert the specified object type; otherwise, <c>false</c>.
        /// </returns>
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof (byte[]);
        }
    }


    /// <summary>
    /// Encodes bytes into websafe base 64
    /// </summary>
    public static class WebSafeBase64
    {
        #region Helpers

        private static readonly char[] ALPHABET = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
      'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
      'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
      'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '-', '_'};
        /**
         * Mapping table from Base64 characters to 6-bit nibbles.
         */
        private static readonly sbyte[] DECODE = new sbyte[128];
        private static readonly char[] WHITESPACE = { '\t', '\n', '\r', ' ', '\f' };

        static WebSafeBase64()
        {
            for (int i = 0; i < DECODE.Length; i++)
            {
                DECODE[i] = -1;
            }

            for (int i = 0; i < WHITESPACE.Length; i++)
            {
                DECODE[WHITESPACE[i]] = -2;
            }

            for (int i = 0; i < ALPHABET.Length; i++)
            {
                DECODE[ALPHABET[i]] = (sbyte)i;
            }
        }


        private static byte GetByte(int i)
        {
            if (i < 0 || i > 127 || DECODE[i] == -1)
            {
                throw new Base64DecodingException("Invalid Encoding");
            }
            return (byte)DECODE[i];
        }

        /// <summary>
        /// Decoding exception
        /// </summary>
        public class Base64DecodingException : Exception
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="Base64DecodingException"/> class.
            /// </summary>
            /// <param name="message">The message.</param>
            public Base64DecodingException(string message)
            {

            }
        }

        private static bool IsWhiteSpace(int i)
        {
            return DECODE[i] == -2;
        }

        #endregion

        /// <summary>
        /// Encodes the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public static char[] Encode(byte[] input)
        {
            int inputBlocks = input.Length / 3;
            int remainder = input.Length % 3;
            int outputLen = inputBlocks * 4;

            switch (remainder)
            {
                case 1:
                    outputLen += 2;
                    break;
                case 2:
                    outputLen += 3;
                    break;
            }

            char[] outChar = new char[outputLen];
            int outPos = 0;
            int inPos = 0;

            for (int i = 0; i < inputBlocks; i++)
            {
                int buffer = (0xFF & input[inPos++]) << 16 | (0xFF & input[inPos++]) << 8
                    | (0xFF & input[inPos++]);
                outChar[outPos++] = ALPHABET[(buffer >> 18) & 0x3F];
                outChar[outPos++] = ALPHABET[(buffer >> 12) & 0x3F];
                outChar[outPos++] = ALPHABET[(buffer >> 6) & 0x3F];
                outChar[outPos++] = ALPHABET[buffer & 0x3F];
            }

            if (remainder > 0)
            {
                int buffer = (0xFF & input[inPos++]) << 16;
                if (remainder == 2)
                {
                    buffer |= (0xFF & input[inPos++]) << 8;
                }
                outChar[outPos++] = ALPHABET[(buffer >> 18) & 0x3F];
                outChar[outPos++] = ALPHABET[(buffer >> 12) & 0x3F];
                if (remainder == 2)
                {
                    outChar[outPos++] = ALPHABET[(buffer >> 6) & 0x3F];
                }
            }
            return outChar;
        }

        /// <summary>
        /// Decodes the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public static Byte[] Decode(char[] input)
        {
            int inLen = input.Length;
            if(inLen ==0)
                return new byte[0];
            // Trim up to two trailing '=' padding characters
            if (input[inLen - 1] == '=')
            {
                inLen--;
            }
            if (input[inLen - 1] == '=')
            {
                inLen--;
            }

            // Ignore whitespace
            int whiteSpaceChars = 0;
            foreach (char c in input)
            {
                if (IsWhiteSpace(c))
                {
                    whiteSpaceChars++;
                }
            }

            inLen -= whiteSpaceChars;
            int inputBlocks = inLen / 4;
            int remainder = inLen % 4;
            int outputLen = inputBlocks * 3;
            switch (remainder)
            {
                case 1:
                    throw new Base64DecodingException("Invalid Length");
                case 2:
                    outputLen += 1;
                    break;
                case 3:
                    outputLen += 2;
                    break;
            }
            byte[] outChar = new byte[outputLen];
            int buffer = 0;
            int buffCount = 0;
            int outPos = 0;
            for (int i = 0; i < inLen + whiteSpaceChars; i++)
            {
                if (!IsWhiteSpace(input[i]))
                {
                    buffer = (buffer << 6) | GetByte(input[i]);
                    buffCount++;
                }
                if (buffCount == 4)
                {
                    outChar[outPos++] = (byte)(buffer >> 16);
                    outChar[outPos++] = (byte)(buffer >> 8);
                    outChar[outPos++] = (byte)buffer;
                    buffer = 0;
                    buffCount = 0;
                }
            }
            switch (buffCount)
            {
                case 2:
                    outChar[outPos++] = (byte)(buffer >> 4);
                    break;
                case 3:
                    outChar[outPos++] = (byte)(buffer >> 10);
                    outChar[outPos++] = (byte)(buffer >> 2);
                    break;
            }

            return outChar;
        }
    }


}
