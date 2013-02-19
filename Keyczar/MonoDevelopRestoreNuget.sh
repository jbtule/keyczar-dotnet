#!/bin/sh -x
mkdir -p packages
cd packages
for i in .nuget Keyczar KeyczarTest KeyczarTool KeyczarTool.Minified
  do mono --runtime=v4.0 ../.nuget/NuGet.exe install ../$i/packages.config
done
cd ..

