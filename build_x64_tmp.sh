#!/bin/bash

# set -e
# set -x

echo $plat_form

version="2.0.0.46"
#make -C backend/osec_backend
#make -C kernel/con_client

echo "111111"
#mkdir -p package/osec
#strip backend/MagicArmor_0 -o package/osec/MagicArmor_0
#strip backend/MagicArmor_1 -o package/osec/MagicArmor_1
#strip kernel/con_client/libOsecKernel.so -o package/osec/libOsecKernel.so
#echo "111111"

#mkdir -p output
sed -i -e '/VERSION=/d' `grep -rl "VERSION=2." package/deb/packdir/opt/osec/net_info.ini`
sed -i -e '/VERSION=/d' `grep -rl "VERSION=2." package/rpm/BUILDROOT/opt/osec/net_info.ini`
echo "VERSION=$version" >> `grep -rl MID= package/deb/packdir/opt/osec/net_info.ini`
echo "VERSION=$version" >> `grep -rl MID= package/rpm/BUILDROOT/opt/osec/net_info.ini`
echo "begin package"
#cp -rf kernel/con_kernel/output/osec_base.ko* package/osec/
cd package/rpm && bash build.sh $version && cd ../../ 
mv package/rpm/RPMS/x86_64/*.rpm output 

cd package/deb && bash build.sh $version && cd ../../ 
mv package/deb/output/*.deb output 
