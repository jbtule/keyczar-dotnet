@echo off
..\.nuget\nuget.exe pack Keyczar.nuspec
..\.nuget\nuget.exe pack Keyczar.nuspec -symbols
