#!/bin/bash
#
# After generating agent wallets with create_agent_wallets.sh and signing the CSRs,
# save each signed cert to the ~/agentwallets/hostname/ directory, login to EMCLI
# as your EM13c Oracle software owner and run this script to import the signed 
# certificates and trusted cert to each wallet, then run the commands listed 
# on screen to deploy wallets to your agents.
#
# Tested against an in-house OpenSSL root CA. This script will require changes to 
# include an additional trusted cert if your CA requires a chain certificate.
#
# @BrianPardy 20161229
# 
# Public domain. Use at your own risk.

EMCLI=$MW_HOME/bin/emcli
AGENTWALLETDIR=~/agentwallets
AGENTWALLETPWD="REDACTED"
ORAPKI=$MW_HOME/oracle_common/bin/orapki
WALLETDN="CN=XXXREPLACEXXX,OU=EM,O=MyCompany,L=MyCity,ST=VT,C=US"
TRUSTED_CERT_LOC=/oracle/oem/trusted_cert.txt

$EMCLI sync
NOT_LOGGED_IN=$?

if [[ $NOT_LOGGED_IN > 0 ]]; then
	echo "Login to EMCLI with \"$EMCLI login -username=USER\" then run this script again"
	exit 1
fi

#mkdir $AGENTWALLETDIR
cd $AGENTWALLETDIR

for agent in `$EMCLI get_targets -targets=oracle_emd | grep oracle_emd | awk '{print $4}'`
do
	agenthostcn=`echo $agent | awk -F: '{print $1}'`
	CERTFILE="$agenthostcn/$agenthostcn.cert"

	if [[ ! -r $CERTFILE ]]; then 
		echo "No signed certificate found for $agenthostcn, skipping"
	else
		echo "Adding root certificate to $agenthostcn wallet"
		$ORAPKI wallet add -wallet $agenthostcn -trusted_cert -cert $TRUSTED_CERT_LOC -pwd $AGENTWALLETPWD
		echo "Adding signed certificate to $agenthostcn wallet"
		$ORAPKI wallet add -wallet $agenthostcn -user_cert -cert $agenthostcn/${agenthostcn}.cert -pwd $AGENTWALLETPWD
		echo
		echo "If all went well, deploy the new $agenthostcn wallet to $agent"
        echo "(stop agent ; copy cwallet.sso to \$AGENT_HOME/agent_inst/sysman/config/server ; start agent)"
	fi
done
