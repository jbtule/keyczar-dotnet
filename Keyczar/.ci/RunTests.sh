#!/bin/sh -x

runTest(){
    mono --runtime=v4.0 packages/nunit.runners/2.6.1/tools/nunit-console.exe -noxml -nodots -labels -stoponerror $@
   if [ $? -ne 0 ]
   then   
     exit 1
   fi
}

runTest KeyczarTest/bin/Debug/net40/KeyczarTest.dll -exclude=Performance

exit $?
