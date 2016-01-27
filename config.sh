#!/bin/bash

export mellanox_debug=no
export CFLAGS="-I/hpc/scrap/artemp/Alltoall/Bruck_mem_copy_ovh/libibprof_install/include/"
export LDFLAGS="-L/hpc/scrap/artemp/Alltoall/Bruck_mem_copy_ovh/libibprof_install/lib/ -libprof -lpthread -ldl -libverbs"
./configure --prefix=/hpc/scrap/artemp/Alltoall/Bruck_mem_copy_ovh/ompi_install \
	    --with-slurm --with-pmi
