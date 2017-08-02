@echo off
IF %2.==. GOTO WrongArgs

..\.nuget\nuget.exe push %1.nupkg %2
..\.nuget\nuget.exe push %1.symbols.nupkg %2 -source http://nuget.gw.symbolsource.org/Public/NuGet

:WrongArgs
ECHO "PublishNuget <pkgname> <apikey>"
