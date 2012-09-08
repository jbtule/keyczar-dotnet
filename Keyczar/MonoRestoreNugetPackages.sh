#!/bin/sh
mkdir packages
cd packages
mono --runtime=v4.0 ../.nuget/nuget.exe install ../Keyczar/packages.config
mono --runtime=v4.0 ../.nuget/nuget.exe install ../KeyczarTest/packages.config
mono --runtime=v4.0 ../.nuget/nuget.exe install ../KeyczarTool/packages.config


