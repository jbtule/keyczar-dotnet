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

namespace Keyczar.Util
{
    /// <summary>
    /// Caches a password prompt result so it doesn't prompt for multiple uses.
    /// </summary>
    public class CachedPrompt : IDisposable
    {
        /// <summary>
        /// Returns a cached version of the prompt
        /// </summary>
        /// <param name="passwordPrompt">The password prompt.</param>
        /// <returns></returns>
        public static CachedPrompt Password(Func<string> passwordPrompt)
        {
            return new CachedPrompt(passwordPrompt);
        }


        private Func<string> _passwordPrompt;
        private bool _prompted;
        private string _password;


        /// <summary>
        /// Initializes a new instance of the <see cref="CachedPrompt"/> class.
        /// </summary>
        /// <param name="passwordPrompt">The password prompt.</param>
        public CachedPrompt(Func<string> passwordPrompt)
        {
            _passwordPrompt = passwordPrompt;
        }


        /// <summary>
        /// Prompts for the password
        /// </summary>
        /// <returns></returns>
        public string Prompt()
        {
            if (!_prompted && _passwordPrompt != null)
            {
                _password = _passwordPrompt();
                _prompted = true;
            }
            return _password;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="CachedPrompt" /> class.
        /// </summary>
        ~CachedPrompt()
        {
            Dispose(false);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            _passwordPrompt = null;
        }
    }
}