#!/bin/bash

export STDERR_COLOR="red" && \
export LD_PRELOAD="$(pwd)/stderr-in-color.so" && \
bash
