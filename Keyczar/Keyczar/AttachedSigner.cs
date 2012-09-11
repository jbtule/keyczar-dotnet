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
using System.IO;
namespace Keyczar
{
	public class AttachedSigner:AttachedVerifier
	{
		Signer _signer;

		/// <summary>
		/// Initializes a new instance of the <see cref="AttachedSigner"/> class.
		/// </summary>
		/// <param name="keySetLocation">The key set location.</param>
		public AttachedSigner(string keySetLocation) : this(new KeySet(keySetLocation))
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="AttachedSigner"/> class.
		/// </summary>
		/// <param name="keySet">The key set.</param>
		public AttachedSigner(IKeySet keySet) : base(keySet)
		{
			throw new NotImplementedException();

		}

		public string Sign(String rawData,Byte[] hidden =null)
		{
			throw new NotImplementedException();

		}
		

		public byte[] Sign(byte[] rawData, Byte[] hidden =null)
		{
			throw new NotImplementedException();
		}
		
		/// <summary>
		/// Signs the specified data.
		/// </summary>
		/// <param name="data">The data.</param>
		/// <param name="signedData">The data with attached signature.</param>
		/// <returns></returns>
		public void Sign(Stream data, Stream signedData, Byte[] hidden =null)
		{
			throw new NotImplementedException();
		}

		protected class AttachedSignerHelper:Signer
		{
			/// <summary>
			/// Initializes a new instance of the <see cref="AttachedSignerHelper"/> class.
			/// </summary>
			/// <param name="keySet">The key set.</param>
			public AttachedSignerHelper(IKeySet keySet)
				: base(keySet)
			{
				
			}

		}



	}
}

