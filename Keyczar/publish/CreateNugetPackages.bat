@echo off
..\.nuget\nuget.exe install ILMerge -version 2.12.0803 -outputdirectory bin
mkdir bin\keyczartool
bin\ILMerge.2.12.0803\ILMerge.exe /copyattrs /lib:"..\KeyczarTool\bin\Release" /targetplatform:v4,"%ProgramFiles%\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0"  /target:exe /wildcards /out:"bin\keyczartool\KeyczarTool.exe" "KeyczarTool.exe" "*.dll"
..\.nuget\nuget.exe pack Keyczar.nuspec
..\.nuget\nuget.exe pack Keyczar.nuspec -symbols
