#!/bin/bash

# set -e
# set -x

echo $plat_form

make -C backend/osec_backend
make -C kernel/con_client

strip backend/MagicArmor_0 -o package/osec/MagicArmor_0
strip backend/MagicArmor_1 -o package/osec/MagicArmor_1
strip kernel/con_client/libOsecKernel.so -o package/osec/libOsecKernel.so

cp -f kernel/con_kernel/osec_base.ko-4.4.58-20170818.kylin.5.desktop-generic package/osec/osec_base.ko-4.4.58-20170818.kylin.5.desktop-generic
