#!/bin/bash
#set -ex

#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/3.10.0-514.el7.x86_64
#mv osec_base.ko osec_base.ko-3.10.0-514-centos
mkdir output
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.4.0-142-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-16-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-15-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.0-6-amd64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/centos/3.10.0-1062.12.1.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/centos/3.10.0-1127.10.1.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-229.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/centos/3.10.0-327.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_ubuntu/4.4.0-148-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_ubuntu/4.4.0-21-generic/build -j8
bash clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-88-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/2.6.32-642.el6.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/2.6.32-696.el6.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/2.6.32-504.el6.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/3.10.0-514.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/3.10.0-693.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/3.10.0-862.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-30deepin-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-212-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.8.0-36-generic/build -j8 
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-42-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.119-20.0009.20/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-348.el8.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.119-20.0009.20/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-213-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-81-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-957.el7.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-23.4.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-118-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-167-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-20-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-862.14.4.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-957.21.3.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1062.18.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1127.19.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.119.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.92.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.25.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.114.2.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-123.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.6.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/2.6.32-431.el6.x86_64/build 

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-55-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1062.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.76.1.el7.x86_64/build
#有点问题
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/4.19.90-2312.1.0.0255.oe2003sp4.x86_64/build
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/4.18.0-553.el8_10.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.12.14-120-default/4.12.14-120/4.12.14-120-default/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.12.11-201.nk.1.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.4.13-200.nd7.1.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-693.2.2.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.95.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1062.9.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-957.12.2.el7.x86_64/build
