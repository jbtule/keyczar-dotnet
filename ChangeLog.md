### Keyczar dotnet v 0.7.5.4 (Beta) February 11, 2013

 - Added Unofficial RSA-PSS signing implementation with appropriate strength digest hash algorithms.		 
 - Made changes to AES-GCM implementation to improve performance when next Bouncy Castle is released.
 - Better implementation for handling key hash collisions.
 - Added missing test check against version number for future ciphetext formats.
 - Removed dependencies on System.Security.Cryptography.
 - No longer uses dynamic invocation, more likely to be AOT compile compatible.
 - Works when encountering a buggy cpp key hash.
 - Works when encountering a buggy java signature.

### Keyczar dotnet v 0.7.5.3 (Beta) January 23, 2013
 
 - Fixed TimeoutSigner compatibilty with other keyczar.
 - Keyczar tool updated 'usekey' to produce all keyczar wire formats.
 - TimeoutVerifier now has optional call back for current time.
 
### Keyczar dotnet v 0.7.5.2 (Beta) January 19, 2013
  
 - Fixed bug with constant time compare not really being constant time
 - Added support to export PEM formatted Public Keys
 - Fixed bug with 'KeyczarTool.exe create' producing python incompatible keysets when --name flag was ommited
 
### Keyczar dotnet v 0.7.5.1 (Beta) January 4, 2013
 - Initial release