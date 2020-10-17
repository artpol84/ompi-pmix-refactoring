#!/bin/bash

./configure --prefix=`pwd`/install \
            --with-ucx=/tmp/hpcx-v2.7.0-gcc-MLNX_OFED_LINUX-5.1-0.6.6.0-redhat7.6/ucx \
            --enable-mca-no-build=coll-ml,btl-uct \
            --with-verbs=no \
            --enable-orterun-prefix-by-default=yes \
            --enable-debug \
            CFLAGS="-O0 -g" CXXFLAGS="-O0 -g"