#!/bin/bash

HOST=$1
DIR=$2

rsync -ra $DIR/* $HOST:$DIR