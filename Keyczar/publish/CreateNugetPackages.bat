@echo off
rmdir tmp /S /Q
mkdir tmp
copy /Y ..\..\ChangeLog.md tmp
copy /Y ..\..\Algorithms.md tmp
copy /Y ..\..\README.md tmp
cd tmp
ren *.md *.txt
cd ..
..\.nuget\nuget.exe pack Keyczar.nuspec
..\.nuget\nuget.exe pack Keyczar.nuspec -symbols
