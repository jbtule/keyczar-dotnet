#!/bin/sh -x

runTest(){
    mono --runtime=v4.0 packages/NUnit.Runners.2.6.1/tools/nunit-console.exe -noxml -nodots -labels -stoponerror $@
   if [ $? -ne 0 ]
   then   
     exit 1
   fi
}

runTest KeyczarTest/bin/Debug/KeyczarTest.dll -exclude=Performance

exit $?
