# Keyczar dotnet [![Nugut Install](https://img.shields.io/nuget/v/Keyczar.svg)](https://www.nuget.org/packages/Keyczar)
Implmemented in C# to match up with the Java/Python/C++ Keyczar standard features
and will interoperate with them by default, however also has stronger crypto and more flexable features when compatiblity is not necessary. Uses BouncyCastle as backend for most encryption.

 - Keyczar-dotnet: http://jbtule.github.io/keyczar-dotnet
 - Official keyczar site: http://keyczar.org

## Usage 

`KeyczarTool.exe` provides the primary mechanism for creating and managing keysets.
Calling `KeyczarTool.exe` from the commandline without flags will display usage.

See [Wiki](http://github.com/jbtule/keyczar-dotnet/wiki) for more info.

## Dependencies

 - .net 4.0 or mono v2.10

#### Keyczar.dll 

 - [BouncyCastle 1.8.0 or later](http://www.bouncycastle.org/csharp/)
 - [DotNetZip 1.10 later](https://github.com/haf/DotNetZip.Semverd)
 - [Newtonsoft.Json 4.5.8 or later](http://json.codeplex.com/)

#### KeyczarTool.exe

 - [ManyConsole 0.4.2.8 or later](https://github.com/fschwiet/ManyConsole)
 - [NDesk.Options 0.2.1 or later](http://www.ndesk.org/Options)
 
## Source & Build

Source code can be obtained with

    git clone --recursive https://github.com/jbtule/keyczar-dotnet.git

Source can be built with msbuild 15, [Rider](https://www.jetbrains.com/rider/), Visual Studio for Mac 7.1, or Visual Studio 2017. More info about building, especially on mono can be found on the [wiki](https://github.com/jbtule/keyczar-dotnet/wiki/Building%20or%20Testing%20Keyczar%20dotnet%20in%20Depth).

Windows | Mac | Linux
------ | ------ | --------
[![Build Status][WinImgMaster]][WinLinkMaster] | [![Build Status][MacImgMaster]][MacLinkMaster] | [![Build Status][TuxImgMaster]][TuxLinkMaster]

[WinImgMaster]:https://ci.appveyor.com/api/projects/status/5p0wfhgroa8a9f4t/branch/master?svg=true
[WinLinkMaster]:https://ci.appveyor.com/project/jbtule/keyczar-dotnet-l0us4/branch/master
[MacImgMaster]:https://travis-matrix-badges.herokuapp.com/repos/jbtule/keyczar-dotnet/branches/master/2

[MacLinkMaster]:https://travis-ci.org/jbtule/keyczar-dotnet
[TuxImgMaster]:https://travis-matrix-badges.herokuapp.com/repos/jbtule/keyczar-dotnet/branches/master/1
[TuxLinkMaster]:https://travis-ci.org/jbtule/keyczar-dotnet


## Compatibility

 - Should interoperate with java/python/c++ with offical api how ever the offical versions of keyczar are very behind in crypto algorithms. If you don't need compatiblity I recommend using the unofficial key types.
 - Unofficial/incompatible api changes are under the unofficial names space to be clear what is provided that won't interoperate with java/python/c++.
 - MutableKeySet is only backward compatible with official keysets stores when reading keys. While it will store the keys differently than official keyczar, it still can produce and decrypt ciphertext compatible with official keyczar.
 - Unofficial algorithms included are *AES-GCM* (`KeyType=C#_AES_AEAD`), RSA-PSS (`KeyType=C#_RSA_SIGN_PRIV`),HMAC-SHA2 (`KeyType=C#_HMAC_SHA2`), and AES-HMAC-SHA2 (`KeyType=C#_HMAC_SHA2`). To use them use unofficial flag on the KeyczarTool.
 - If you have an existing keyset and you didn't create with the --unofficial flag, `--force` will be required to add an unofficial key type.
 - `VanillaSigner` and `VanillaVerifier` are feature identical to java/python/c++ `UnversionedSigner` and `UnversionVerifer`
 - The Functionality of java/python/c++ `SessionEncrypter`, `SessionDecrypter`, `SignedSessionEncrypter`, and `SignedSessionDecrypter` are provided by the C# `SessionCrypter` via constructor arguments.
 - You can use the AppSetting `keyczar.strict_dsa_verification` if you don't need java Keyczar compatiblity and need stricter verification of dsa sigs.


## Contribute ##

Code contribution, reported issues or code reviews welcome! Pull requests are automatically built and tested with [Travis CI][MacLinkMaster] and [AppVeyor][WinLinkMaster].
