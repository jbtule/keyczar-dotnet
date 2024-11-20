# Keyczar dotnet [![Nugut Install](https://img.shields.io/nuget/v/Keyczar.svg)](https://www.nuget.org/packages/Keyczar)
Implmemented in C# to match up with the Java/Python/C++ Keyczar standard features
and will interoperate with them by default, however also has stronger crypto and more flexable features when compatiblity is not necessary. Uses BouncyCastle as backend for most encryption.

 - Keyczar-dotnet: http://jbtule.github.io/keyczar-dotnet
 - Official keyczar site: http://keyczar.org

## Usage 

`KeyczarTool.exe` provides the primary mechanism for creating and managing keysets.
Calling `KeyczarTool.exe` from the commandline without flags will display usage.

See [Wiki](http://github.com/jbtule/keyczar-dotnet/wiki) for more info.

## Targets

 - .NET 4 and .NET Standard 2.0

#### Keyczar.dll 

 - [BouncyCastle(http://www.bouncycastle.org/csharp/)
 - [SharpZipLib](https://github.com/icsharpcode/SharpZipLib)
 - [Newtonsoft.Json](https://www.newtonsoft.com/json)
 - [Newtonsoft.Json.Bson](https://github.com/JamesNK/Newtonsoft.Json.Bson)

#### KeyczarTool.exe

 - [ManyConsole.CommandLineUtils](https://github.com/jbtule/ManyConsole.CommandLineUtils)
 - [McMaster.Extensions.CommandLineUtils](https://github.com/natemcmaster/CommandLineUtils)
 
## Source & Build

Source code can be obtained with

    git clone --recursive https://github.com/jbtule/keyczar-dotnet.git

Source can be built with msbuild, [Rider](https://www.jetbrains.com/rider/), or Visual Studio. .

| Windows                                        | Linux                                          |
|------------------------------------------------|------------------------------------------------|
| [![Build Status][WinImgMaster]][WinLinkMaster] | [![Build Status][TuxImgMaster]][TuxLinkMaster] |

[WinImgMaster]:https://github.com/jbtule/keyczar-dotnet/actions/workflows/dotnet48.yml/badge.svg
[WinLinkMaster]:https://github.com/jbtule/keyczar-dotnet/actions/workflows/dotnet48.yml

[TuxImgMaster]:https://github.com/jbtule/keyczar-dotnet/actions/workflows/dotnet.yml/badge.svg
[TuxLinkMaster]:https://github.com/jbtule/keyczar-dotnet/actions/workflows/dotnet.yml


## Compatibility

 - Should interoperate with java/python/c++ with offical api how ever the offical versions of keyczar are very behind in crypto algorithms. If you don't need compatiblity I recommend using the unofficial key types.
 - Unofficial/incompatible api changes are under the unofficial names space to be clear what is provided that won't interoperate with java/python/c++.
 - MutableKeySet is only backward compatible with official keysets stores when reading keys. While it will store the keys differently than official keyczar, it still can produce and decrypt ciphertext compatible with official keyczar.
 - Unofficial algorithms included are *AES-GCM* (`KeyType=C#_AES_AEAD`), RSA-PSS (`KeyType=C#_RSA_SIGN_PRIV`),HMAC-SHA2 (`KeyType=C#_HMAC_SHA2`), and AES-HMAC-SHA2 (`KeyType=C#_HMAC_SHA2`). To use them use unofficial flag on the KeyczarTool.
 - If you have an existing keyset and you didn't create with the --unofficial flag, `--force` will be required to add an unofficial key type.
 - `VanillaSigner` and `VanillaVerifier` are feature identical to java/python/c++ `UnversionedSigner` and `UnversionVerifer`
 - The Functionality of java/python/c++ `SessionEncrypter`, `SessionDecrypter`, `SignedSessionEncrypter`, and `SignedSessionDecrypter` are provided by the C# `SessionCrypter` via constructor arguments.
 - You can use the AppSetting `keyczar.strict_dsa_verification` if you don't need java Keyczar compatiblity and need stricter verification of dsa sigs.
