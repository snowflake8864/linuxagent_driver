
find ./ -name "Module.symvers" | xargs -I {} rm -f {}
find ./ -name "*.o" | xargs -I {} rm -f {}
find ./ -name "*.ko" | xargs -I {} rm -f {}
find ./ -name "*.cmd" | xargs -I {} rm -f {}
find ./ -name "*.mod.c" | xargs -I {} rm -f {}

