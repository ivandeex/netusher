#!/bin/sh
# openvpn debugging
# $Id: 01-any-any-debug.sh 105 2011-02-02 00:35:47Z vitki $
if [ x$RC_DEBUG = x1 ]; then
    excluded="$excluded|_|CVS_RSH|G_BROKEN_FILENAMES|HISTSIZE|HOME|HOSTNAME"
    excluded="$excluded|JAVA_HOME|LANG|LESSOPEN|LOGNAME|LS_COLORS|MAIL|NXDIR|PATH|PWD"
    excluded="$excluded|SHELL|SHLVL|SSH_CLIENT|SSH_CONNECTION|SSH_TTY|TERM|USER|VISUAL"
    env | egrep -v "^($excluded)=" | sort
fi
