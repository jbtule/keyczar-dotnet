#!/bin/sh -x
mozroots --import --sync
cp .nuget/NuGet.* .ci/
mkdir -p packages
cd packages
mono --runtime=v4.0 ../.ci/NuGet.exe install ../.nuget/packages.config
mono --runtime=v4.0 ../.ci/NuGet.exe install ../Keyczar/packages.config
mono --runtime=v4.0 ../.ci/NuGet.exe install ../KeyczarTest/packages.config
mono --runtime=v4.0 ../.ci/NuGet.exe install ../KeyczarTool/packages.config
mono --runtime=v4.0 ../.ci/NuGet.exe install ../KeyczarTool.Minified/packages.config
cd ..

