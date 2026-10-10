#!/bin/bash
#set -ex

#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/3.10.0-514.el7.x86_64
#mv osec_base.ko osec_base.ko-3.10.0-514-centos
mkdir output
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.4.0-142-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-72-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-16-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-15-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-305.3.1.el8.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-55-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.0-6-amd64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_ubuntu/4.4.0-148-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_ubuntu/4.4.0-21-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-348.el8.x86_64/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.119-20.0009.20/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-81-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-131-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.19.0-43-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.19.0-21-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.19.0-46-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-42-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.3.0-53-generic/build -j8
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.219-1.el7.elrepo.x86_64/build -j8 
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-43-generic/build -j8 
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.5.0-28-generic/build -j8 
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.2.0-26-generic/build -j8 
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.5.0-41-generic/build -j8 
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.0-91.82.179.uelc20.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.90-89.11.v2401.ky10.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-444.el9.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-182-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.119-20.0009.31/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-540.el8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-107-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-23.4.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.2.9-300.fc38.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.0.7-301.fc37.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.18.18-100.fc35.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.16.15-101.fc34.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.11.7-200.fc33.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.5.0-35-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.1.0-21-amd64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.1.0-21-amd64/build clean
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.1.0-22-amd64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.1.0-22-amd64/build clean
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-67-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-84-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-70.30.1.el9_0.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-162.23.1.el9_1.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-284.30.1.el9_2.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-362.24.1.el9_3.0.1.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-362.24.1.el9_3.0.1.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-427.18.1.el9_4.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-26-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-106-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-113-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-348.20.1.el8_5.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-372.32.1.el8_6.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-425.19.2.el8_7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-477.27.1.el8_8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-477.21.1.el8_8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-513.18.1.el8_9.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-427.22.1.el9_4.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-362.24.2.el9_3.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-284.11.1.el9_2.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.14.0-70.26.1.el9_0.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-28.2.al7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-28.7.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.134-16.3.al8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.134-15.al8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.134-17.1.al8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.134-16.1.al8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.134-13.1.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-26.6.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-26.5.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-27.1.an7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-26.an7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-26.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-372.9.1.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-25.7.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.91-24.8.an7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-190-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-118-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-20-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-213-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-167-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-30deepin-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-212-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.25.1.el7.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.2.0-20-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.2.0-39-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-45-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-47-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-49-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-65-generic/build
bash  clean.sh

make KPATH=/root/code/code/linux/kernel/5.4.272-1.el7.elrepo.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-60-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-157-generic/build
bash  clean.sh

make KPATH=/root/code/code/linux/kernel/5.15.0-131-generic/build

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.0-9-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-193.el8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.17.11-1.el7.elrepo.x86_64/build

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.19.0-32-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-69-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-91-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-102-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-57-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-50-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-51-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-58-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-169-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-192-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-79-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-85-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-83-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-84-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/6.8.0-87-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.278-1.el7.elrepo.x86_64/build
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/4.18.0-553.el8_10.x86_64/build
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/4.18.0-553.109.1.el8_10.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-372.9.1.el8.x86_64/build
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/4.19.90-2312.1.0.0255.oe2003sp4.x86_64/build
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/4.19.90-2112.8.0.0131.oe1.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-87-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-164-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-136-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.10.134-18.an8.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-171-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.13.5-1.el7.elrepo.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-119-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-143-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-181-generic/build
#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/6.8.0-90-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-161-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.18-132-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.18-110-generic/build

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-167-generic/build

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-212-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-213-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-88-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.90-89.40.v2401.ky10.x86_64/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-216-generic/build
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.15.0-174-generic/build
