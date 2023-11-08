#!/bin/env /bin/zsh

sudo setcap CAP_NET_BIND_SERVICE=+eip ${HOME}/devel/fuzzy-carnival/target/debug/pierre3
