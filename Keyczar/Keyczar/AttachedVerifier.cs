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
	public class AttachedVerifier:Keyczar
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="AttachedSigner"/> class.
		/// </summary>
		/// <param name="keySetLocation">The key set location.</param>
		public AttachedVerifier(string keySetLocation)
			: base(keySetLocation)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="AttachedSigner"/> class.
		/// </summary>
		/// <param name="keySet">The key set.</param>
		public AttachedVerifier(IKeySet keySet) : base(keySet)
		{
			if (keySet.Metadata.Purpose != KeyPurpose.VERIFY
			    && keySet.Metadata.Purpose != KeyPurpose.SIGN_AND_VERIFY)
			{
				throw new InvalidKeyTypeException("This key set can not be used for verifying signatures.");
			}
		}


		public bool Verify(string message, byte[] hidden =null){
			throw new NotImplementedException();
		}
		
		public bool Verify(byte[] message, byte[] hidden =null){
			throw new NotImplementedException();
		}

		public bool Verify(Stream message, byte[] hidden =null){
			throw new NotImplementedException();
		}
	}
}

