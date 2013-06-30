# Keyczar dotnet 
Implmemented in C# 4 to match up with the Java/Python/C++ Keyczar standard features
and will interoperate with them by default. Uses BouncyCastle as backend for most encryption.

 - Keyczar-dotnet: http://jbtule.github.com/keyczar-dotnet
 - Official keyczar site: http://keyczar.org

## Usage 

`KeyczarTool.exe` provides the primary mechanism for creating and managing keysets.
Calling `KeyczarTool.exe` from the commandline without flags will display usage.

See [Wiki](http://github.com/jbtule/keyczar-dotnet/wiki) for more info.

## Dependencies

 - .net 4.0 or mono v2.10

#### Keyczar.dll 

 - [BouncyCastle 1.7.0 or later](http://www.bouncycastle.org/csharp/)
 - [DotNetZip 1.9.1.8 or later](http://dotnetzip.codeplex.com/)
 - [Newtonsoft.Json 4.5.8 or later](http://json.codeplex.com/)

#### KeyczarTool.exe

 - [ManyConsole 0.4.2.8 or later](https://github.com/fschwiet/ManyConsole)
 - [NDesk.Options 0.2.1 or later](http://www.ndesk.org/Options)
 
## Source & Build

Source code can be obtained with

    git clone --recursive https://github.com/jbtule/keyczar-dotnet.git

Source can be built with Visual Studio 2012, MonoDevelop, msbuild, or xbuild using the Keyczar.sln as long as you have the nuget dependencies downloaded. More info about building, especially on mono can be found on the [wiki](https://github.com/jbtule/keyczar-dotnet/wiki/Building%20or%20Testing%20Keyczar%20dotnet%20in%20Depth).

Master | Stable | Provider
------ | ------ | --------
[![Build Status][WinImgMaster]][WinLinkMaster] | [![Build Status][WinImgStable]][WinLinkStable] | Windows CI Provided By [CodeBetter][] and [JetBrains][] 
[![Build Status][MonoImgMaster]][MonoLinkMaster] | [![Build Status][MonoImgStable]][MonoLinkStable] | Mono CI Provided by [travis-ci][] 

[WinImgMaster]:http://teamcity.codebetter.com/app/rest/builds/buildType:\(id:bt922\)/statusIcon
[WinLinkMaster]:http://teamcity.codebetter.com/viewLog.html?buildTypeId=bt922&buildId=lastFinished&guest=1
[MonoImgMaster]:https://travis-ci.org/jbtule/keyczar-dotnet.png?branch=master
[MonoLinkMaster]:https://travis-ci.org/jbtule/keyczar-dotnet
[WinImgStable]:http://teamcity.codebetter.com/app/rest/builds/buildType:\(id:bt933\)/statusIcon
[WinLinkStable]:http://teamcity.codebetter.com/viewLog.html?buildTypeId=bt933&buildId=lastFinished&guest=1
[MonoImgStable]:https://travis-ci.org/jbtule/keyczar-dotnet.png?branch=stable
[MonoLinkStable]:https://travis-ci.org/jbtule/keyczar-dotnet


[JetBrains]:http://www.jetbrains.com/
[CodeBetter]:http://codebetter.com/
[travis-ci]:https://travis-ci.org/


## Compatibility

 - Should interoperate with java/python/c++ with standard api
 - All unofficial/incompatible api changes are under the unofficial names space to be clear what is provided that won't interoperate with java/python/c++.
 - Unofficial algorithms included are *AES-GCM* (`KeyType=C#_AES_AEAD`) and RSA-PSS (`KeyType=C#_RSA_SIGN_PRIV`) use the unofficial flag on the KeyczarTool.
 - `VanillaSigner` and `VanillaVerifier` are feature identical to java/python/c++ `UnversionedSigner` and `UnversionVerifer`
 - The Functionality of java/python/c++ `SessionEncrypter`, `SessionDecrypter`, `SignedSessionEncrypter`, and `SignedSessionDecrypter` are provided by the C# `SessionCrypter` via constructor arguments.


