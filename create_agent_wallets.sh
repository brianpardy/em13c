#!/bin/bash
#
# Run this script as your EM13c software owner account after logging in to EMCLI.
# 
# It will generate a wallet for every agent in your environment, contained inside
# ~/agentwallets, as well as a certificate for each agent and a certificate signing
# request to send to your certificate administrator.
#
# Follow the directions on screen once you have received the signed certificate.
#
# @BrianPardy 20161229
#
# Update 20181017: Change EMCLI get_targets call to avoid truncating long agent names
#
# Public domain. Use at your own risk.
#


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

mkdir $AGENTWALLETDIR
cd $AGENTWALLETDIR

for agent in `$EMCLI get_targets -format=name:csv -targets=oracle_emd | grep oracle_emd | awk -F, '{print $4}'`
do
	agenthostcn=`echo $agent | awk -F: '{print $1}'`
	CSRFILE="$agenthostcn/$agenthostcn.csr"
	

	if [[ ! -d $agenthostcn ]]; then
		echo "Creating a wallet for $agent on $agenthostcn"
		mkdir $agenthostcn
		$ORAPKI wallet create -wallet $agenthostcn -auto_login -pwd $AGENTWALLETPWD
		$ORAPKI wallet display -wallet $agenthostcn
	fi

	MYWALLETDN=`echo $WALLETDN | sed "s/XXXREPLACEXXX/$agenthostcn/"`

	echo "Creating certificate with DN=$MYWALLETDN"
	$ORAPKI wallet add -wallet $agenthostcn -dn "$MYWALLETDN" -keysize 2048 -pwd $AGENTWALLETPWD
	$ORAPKI wallet display -wallet $agenthostcn

	if [[ ! -r "$CSRFILE" ]]; then
		echo "Creating CSR for DN=$MYWALLETDN"
		$ORAPKI wallet export -wallet $agenthostcn -dn "$MYWALLETDN" -request "$CSRFILE"
		$ORAPKI wallet display -wallet $agenthostcn

		echo "Created CSR in $CSRFILE, send this file to your certification authority."
		echo "If you run your own with OpenSSL, try this command on your signing server:"
		echo "openssl x509 -req -in $CSRFILE -sha256 -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out ${CSRFILE}.cert -days 1024"
		echo
		echo "Once you have received ${CSRFILE}.cert, first load the root certificate by running: "
		echo "$ORAPKI wallet add -wallet $agenthostcn -trusted_cert -cert $TRUSTED_CERT_LOC -pwd AGENTWALLETPWD"
		echo
		echo "Next, load the signed certificate by running: "
		echo "$ORAPKI wallet add -wallet $agenthostcn -user_cert -cert $agenthostcn/${agenthostcn}.cert -pwd AGENTWALLETPWD"
		echo
	fi
done
