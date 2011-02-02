#!/bin/sh
# openvpn debugging
# $Id$
if [ x$RC_DEBUG = x1 ]; then
    excluded="$excluded|_|CVS_RSH|G_BROKEN_FILENAMES|HISTSIZE|HOME|HOSTNAME"
    excluded="$excluded|JAVA_HOME|LANG|LESSOPEN|LOGNAME|LS_COLORS|MAIL|NXDIR|PATH|PWD"
    excluded="$excluded|SHELL|SHLVL|SSH_CLIENT|SSH_CONNECTION|SSH_TTY|TERM|USER|VISUAL"
    env | egrep -v "^($excluded)=" | sort
fi
