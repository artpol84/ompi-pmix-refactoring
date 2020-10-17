#!/bin/bash

HOST=$1
DIR=$2

rsync $DIR/* $HOST:$DIR