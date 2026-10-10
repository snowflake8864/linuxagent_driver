#!/bin/bash
#set -ex

#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/3.10.0-514.el7.x86_64
#mv osec_base.ko osec_base.ko-3.10.0-514-centos
mkdir output
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.5.6-300.fc39.x86_64/build simple
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-88-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.6.0-32.7.v2505.ky11.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-101-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-71-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.6.0-145.0.2.143.oe2403sp2.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-107-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-110-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-111-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.0-136.35.0.111.u63.fos23.x86_64/build

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.0-15-generic/build

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-90-generic/build
