#!/bin/bash

if [[ -z "${UCX}" ]]; then
source ./hpcx.paths
fi

./configure --prefix=`pwd`/install-rel \
            --with-ucx=${UCX} \
            --with-hcoll=${HCOLL} \
            --with-pmix=internal \
            --enable-mca-no-build=coll-ml,btl-uct \
            --with-verbs=no \
            --enable-orterun-prefix-by-default=yes \
