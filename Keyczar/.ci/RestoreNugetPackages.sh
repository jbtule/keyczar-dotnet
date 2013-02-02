#!/bin/sh -x
mozroots --import --sync
cp .nuget/NuGet.* .ci/
mkdir -p packages
cd packages
for i in .nuget Keyczar KeyczarTest KeyczarTool KeyczarTool.Minified
  do mono --runtime=v4.0 ../.ci/NuGet.exe install ../$i/packages.config
done
cd ..

