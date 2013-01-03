= Keyczar dotnet =
Implmemented in C# 4 to match up with the Java/Python/C++ Keyczar standard features and will interoperate with them by default. Uses BouncyCastle as backend for most encryption. Official keyczar site: http://keyczar.org

== Usage ==

`KeyczarTool.exe` provides the primary mechanism for creating and managing keysets. Calling `KeyczarTool.exe` from the commandline without flags will display usage.

== Dependancies ==

 - .net 4.0 or mono v2.10

==== Keyczar.dll ====

 - [BouncyCastle 1.7.0 or later](http://www.bouncycastle.org/csharp/)
 - [DotNetZip 1.9.1.8 or later](http://dotnetzip.codeplex.com/)
 - [Newtonsoft.Json 4.5.8 or later](http://json.codeplex.com/)

==== KeyczarTool.exe ====

 - [ManyConsole 0.4.2.8 or later](https://github.com/fschwiet/ManyConsole)
 - [NDesk.Options 0.2.1 or later](http://www.ndesk.org/Options)

==== KeyczarTest.dll ====

 - [NUnit 2.6.1 or later](http://www.nunit.org/)


== Build ==

==== Visual Studio 2010 or Later ====

Dependencies should be downloaded automaticially with [nuget](http://nuget.org) which is integrated into the solution. Build all triggers nuget.

==== MonoDevelop v3.0.4 or later =====

Run `MonoRestoreNugetPackages.sh` script first to restore nuget dependency then builds fine from monodevelop. Sometimes nuget.exe under mono has weird null exceptions, repeating running the script usually fixes this issue.

== Compatibility ==

 - Should interoperate with java/python/c++ with standard api
 - All unofficial/incompatible api changes are under the unofficial names space to be clear what won't interoperate with java/python/c++
 - Currently the only unofficial algorithm is *AES-GCM* (`KeyType=C#_AES_AEAD`) using the unofficial flag on the KeyczarTool will use it to replace *AES-Then-HmacSha1*
 - `VanillaSigner` and `VanillaVerifier` are feature identical to `UnversionedSigner` and `UnversionVerifer`
 - The Functionality of `SessionEncrypter`, `SessionDecrypter`, `SignedSessionEncrypter`, and `SignedSessionDecrypter` are provided by `SessionCrypter` via constructor arguments.


