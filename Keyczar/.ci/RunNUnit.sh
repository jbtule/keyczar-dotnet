#!/bin/sh -x
mono packages/NUnit.Runners.2.6.1/tools/nunit-console.exe KeyczarTest/bin/Debug/KeyczarTest.dll -exclude=Performance -noxml -nodots -labels
exit
