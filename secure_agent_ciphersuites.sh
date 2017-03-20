#!/bin/bash
#
# This script will retrieve a list of agents from your EM13cR2 environment,
# check the ciphersuites they allow for connections to the agent,
# and then disable all ciphersuites other than SSL_RSA_WITH_3DES_EDE_CBC_SHA,
# then it will restart each modified agent to apply the change.
#
# As of EM13cR2, only SSL_RSA_WITH_3DES_EDE_CBC_SHA passes openssl's 
# HIGH ciphersuite check.
#
# You need to login to EMCLI first before running this script.
# SYSMAN will work, so will the CHECKSEC account created with my other tools.
#
# Released  v1.0:  Initial beta release 20 Mar 2017
#
# From: @BrianPardy on Twitter
#   https://pardydba.wordpress.com/
#
# Known functional on Linux x86-64

VERSION=1.0
HIGH_STRENGTH_CIPHER=SSL_RSA_WITH_3DES_EDE_CBC_SHA
EMCLI=$MW_HOME/bin/emcli

if [[ -x "/usr/sfw/bin/gegrep" ]]; then
	GREP=/usr/sfw/bin/gegrep
else
	GREP=`which grep`
fi

$EMCLI sync
NOT_LOGGED_IN=$?

if [[ $NOT_LOGGED_IN > 0 ]]; then
	echo "Login to EMCLI with \"$EMCLI login -username=USER\" then run this script again"
	exit 1
fi

for agent in `$EMCLI get_targets -targets=oracle_emd | grep oracle_emd | awk '{print $4}'`
do
    echo -n "Checking ciphersuites on $agent... "
    CURCIPHER=`$EMCLI get_agent_property -agent_name="$agent" -name="SSLCipherSuites" | $GREP "Property Value" | awk '{print $3}' | sed 's/ //g'`

    if [[ "$CURCIPHER" == "$HIGH_STRENGTH_CIPHER" ]]; then
        echo OK
    else
        echo "Failed - $CURCIPHER"

        echo "Setting $agent to use only $HIGH_STRENGTH_CIPHER"
		$EMCLI set_agent_property -agent_name=$agent -name=SSLCipherSuites -value="$HIGH_STRENGTH_CIPHER" -new
		echo
		echo "Restarting $agent to apply changes"
		$EMCLI restart_agent -agent_name=$agent -credential_setname="HostCreds"
		RESTART_RETURN=$?

		if [[ $RESTART_RETURN != 0 ]]; then
			echo "Unable to restart agent: restart agent manually or set preferred host credentials for agent"
		fi

    fi
done

exit 0
