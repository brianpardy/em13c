#!/bin/bash
#
# This script will retrieve a list of agents from your EM13c environment,
# determine if they allow connections using TLS protocol versions older
# than TLSv1.2, and then disable all protocols older than TLSv1.2.
#
# Finally it will restart each modified agent to apply the change.
#
# You need to login to EMCLI first before running this script.
#
# Released  v0.1:  Initial beta release 5 Oct 2016
#
#
# From: @BrianPardy on Twitter
#   https://pardydba.wordpress.com/
#
# Known functional on Linux x86-64, may work on Solaris and AIX.

EMCLI=$MW_HOME/bin/emcli

if [[ -x "/usr/sfw/bin/gegrep" ]]; then
	GREP=/usr/sfw/bin/gegrep
else
	GREP=`which grep`
fi

OPENSSL=`which openssl`

if [[ -x "/usr/bin/openssl1" && -f "/etc/SuSE-release" ]]; then
	OPENSSL=`which openssl1`
fi

OPENSSL_HAS_TLS1_2=`$OPENSSL s_client help 2>&1 | $GREP -c tls1_2`

$EMCLI sync
NOT_LOGGED_IN=$?

if [[ $NOT_LOGGED_IN > 0 ]]; then
	echo "Login to EMCLI with \"$EMCLI login -username=USER\" then run this script again"
	exit 1
fi

for agent in `$EMCLI get_targets -targets=oracle_emd | grep oracle_emd | awk '{print $4}'`
do
	echo
	if [[ $OPENSSL_HAS_TLS1_2 > 0 ]]; then
		echo -n "Checking TLSv1 on $agent... "

		OPENSSL_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $agent -tls1 2>&1 | $GREP Cipher | $GREP -c 0000`

		if [[ $OPENSSL_RETURN == 0 ]]; then
			echo "allows TLSv1"
		else
			echo "already forbids TLSv1"
		fi
	fi

	if [[ $OPENSSL_HAS_TLS1_2 > 0 ]]; then
		echo -n "Checking TLSv1.1 on $agent... "

		OPENSSL_TLS11_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $agent -tls1_1 2>&1 | $GREP Cipher | $GREP -c 0000`

		if [[ $OPENSSL_RETURN == 0 ]]; then
			echo "allows TLSv1.1"
		else
			echo "already forbids TLSv1.1"
		fi
	fi

	if [[ $OPENSSL_RETURN == 0 || $OPENSSL_TLS11_RETURN == 0 ]]; then
		$EMCLI set_agent_property -agent_name=$agent -name=minimumTLSVersion -value=TLSv1.2 -new

		echo
		echo "Restarting $agent to apply changes"
		$EMCLI restart_agent -agent_name=$agent -credential_setname="HostCreds"
		RESTART_RETURN=$?

		if [[ $RESTART_RETURN != 0 ]]; then
			echo "Unable to restart agent: restart agent manually or set preferred host credentials for agent"
		fi
	fi
done

$EMCLI logout

exit 0
