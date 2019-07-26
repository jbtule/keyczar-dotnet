#!/bin/sh -x

runTest(){
    mono --runtime=v4.0 packages/nunit.runners/3.10.1/tools/nunit3-console.exe --noresult --labels=On --workers=1 $@
   if [ $? -ne 0 ]
   then   
     exit 1
   fi
}

runTest KeyczarTest/bin/Debug/net451/KeyczarTest.dll --where "cat != Performance" 

exit $?
