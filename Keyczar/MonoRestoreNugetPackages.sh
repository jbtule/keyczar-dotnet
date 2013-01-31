#!/bin/sh -x
mkdir -p packages
cd packages
mono --runtime=v4.0 ../.nuget/NuGet.exe install ../.nuget/packages.config
mono --runtime=v4.0 ../.nuget/NuGet.exe install ../Keyczar/packages.config
mono --runtime=v4.0 ../.nuget/NuGet.exe install ../KeyczarTest/packages.config
mono --runtime=v4.0 ../.nuget/NuGet.exe install ../KeyczarTool/packages.config
mono --runtime=v4.0 ../.nuget/NuGet.exe install ../KeyczarTool.Minified/packages.config
cd ..

