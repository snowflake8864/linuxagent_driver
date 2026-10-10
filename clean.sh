#!/bin/bash

# set -e
# set -x

make -C backend clean
make -C osec_engine/osec_engine_client clean
make -C osec_engine/osec_engine_server clean
make -C kernel/con_client clean

rm -f package/osec/*.so 
rm -f package/osec/osec_base.ko* 
rm -f package/osec/osecbackend
rm -f package/osec/osecserver
rm -f package/osec/osecnetagent
