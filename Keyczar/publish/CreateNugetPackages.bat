@echo off
rmdir tmp /S /Q
mkdir tmp
copy /Y Algorithms.md ChangeLog.md README.md tmp
ren *.md *.txt
..\.nuget\nuget.exe pack Keyczar.nuspec
..\.nuget\nuget.exe pack Keyczar.nuspec -symbols
