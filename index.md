---
layout: main
title: Keyczar-dotnet by jbtule
---

# Keyczar dotnet #
Implemented in C# 4 to match up with the Java/Python/C++ Keyczar standard features and will interoperate with them by default. Uses BouncyCastle as backend for most encryption. Official keyczar site: http://keyczar.org

## Binary Release ##
`Keyczar.dll` and `KeyczarTool.exe` can be added to your project using [NuGet](http://nuget.org)
```
PM> Install-Package Keyczar -Pre
```
Although it's currently listed as pre-release in NuGet, Keyczar-dotnet currently has over **600** unit tests providing **90%** code coverage and is tested against python and java Keyczar produced data as well. Because it is a security framework I'm going to keep it conservatively listed under pre-release until more eyes have been on the code.

Source Code for debugging NuGet provided binaries can be downloaded automatically in Visual Studio by configuring [SymbolSource.org](http://www.symbolsource.org/Public/Home/VisualStudio).

## Usage ##

`KeyczarTool.exe` provides the primary mechanism for creating and managing keysets. Calling `KeyczarTool.exe` from the command line without flags will display usage. Use it to create your key set first and use it to rotate your keys later.

Once you have your key set the basic api is very simple to use for encryption:
```csharp
string plaintext = "Secret Message"
WebBase64 ciphertext;
//encrypting
using (var encrypter = new Encrypter("path_to_keyset"))
{
    ciphertext = encrypter.Encrypt(plaintext);
}
//decrypting
using (var crypter = new Crypter("path_to_keyset")){
    var plaintext2 = crypter.Decrypt(ciphertext)
}
```
and for signatures:
```csharp
string plaintext = "A Message"
WebBase64 signature;
//signing
using (var signer = new Signer("path_to_keyset"))
{
    signature = signer.Sign(plaintext);
}
//verifying
using (var verifier = new Verifier("path_to_keyset"))
{
    var isVerified = verifier.Verify(plaintext, signature);
}
```

See more usage and documentation in the [Wiki](http://github.com/jbtule/keyczar-dotnet/wiki).

## Dependencies ##

 - .net 4.0 or mono v2.10

#### Keyczar.dll ####

 - [BouncyCastle 1.7.0 or later](http://www.bouncycastle.org/csharp/)
 - [DotNetZip 1.9.1.8 or later](http://dotnetzip.codeplex.com/)
 - [Newtonsoft.Json 4.5.8 or later](http://json.codeplex.com/)

#### KeyczarTool.exe ####

 - [ManyConsole 0.4.2.8 or later](https://github.com/fschwiet/ManyConsole)
 - [NDesk.Options 0.2.1 or later](http://www.ndesk.org/Options)
 - [DiminishDependencies 1.1.3 or later](https://github.com/jbtule/diminish-dependencies)

#### KeyczarTest.dll ####

 - [NUnit 2.6.1 or later](http://www.nunit.org/)

## Build ##

#### Visual Studio 2010 or Later / MSBuild ####

Dependencies should be downloaded automaticially with [NuGet](http://nuget.org) which is integrated into the solution. Build all should trigger nuget to download all dependencies from Visual Studio or MSBuild. 

#### MonoDevelop 3.04 or Later / xbuild ####

Run `MonoRestoreNugetPackages.sh` script first to restore NuGet dependency then you may build from MonoDevelop with `Build All` or with just xbuild run `xbuild Keyczar.sln`.

 - Keyczar
   - master 
     - .Net 4.0 [![Build Status](http://teamcity.codebetter.com/app/rest/builds/buildType:\(id:bt922\)/statusIcon)](http://teamcity.codebetter.com/viewLog.html?buildTypeId=bt922&buildId=lastFinished&guest=1) - Thanks Codeb
     - Mono 2.10 [![Build Status](https://travis-ci.org/jbtule/keyczar-dotnet.png?branch=master)](https://travis-ci.org/jbtule/keyczar-dotnet)

See more in [Building in Depth](http://github.com/jbtule/keyczar-dotnet/wiki/Building-or-Testing-Keyczar-dotnet-in-Depth).

## Contribute ##

Code contribution, reported issues or code reviews welcome! Pull requests are automatically built and tested with [Travis CI](https://travis-ci.org/jbtule/keyczar-dotnet).

## Compatibility ##

 - Should interoperate with java/python/c++ with standard api
 - All unofficial/incompatible api changes are under the unofficial names space to be clear what won't interoperate with java/python/c++
 - Unofficial algorithms included are *AES-GCM* (`KeyType=C#_AES_AEAD`) and RSA-PSS (`KeyType="C#_RSA_SIGN_PRIV") use the unofficial flag on the KeyczarTool.
 - `VanillaSigner` and `VanillaVerifier` are feature identical to java/python/c++ `UnversionedSigner` and `UnversionedVerifer`
 - The Functionality of java/python/c++ `SessionEncrypter`, `SessionDecrypter`, `SignedSessionEncrypter`, and `SignedSessionDecrypter` are provided by the C# `SessionCrypter` via constructor arguments.