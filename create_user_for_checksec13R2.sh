#!/bin/bash
#
# To use this script, first login to EMCLI with an administrative user account.
#
# The script will create a new OEM user for checksec13R2.sh, with a random password.
# The user will receive the permissions necessary to execute all of the EMCLI-based
# checks used by checksec13R2.sh 
#
# EM_ALL_OPERATOR works to allow CHECKSEC user to ./emcli execute_sql.
#
# Brian J. Pardy
# 20170313
#
# This script makes a few assumptions.
#   - All of your saved credentials have SYSMAN as their owner
#     * Update the OEM_CREDENTIAL_OWNER variable if you use another owner.
#   - /dev/urandom exists on your system (try /dev/random if not)
#

VERSION=0.2
RELDATE="20170313"

EMCLI="$MW_HOME/bin/emcli"
OEM_USER=CHECKSEC
OEM_USER_PW=`cat /dev/urandom | tr -dc 'a-zA-Z0-9-_!#^*_+|?=' | fold -w 16 | head -n 1`
OEM_CREDENTIAL_OWNER=SYSMAN
DOAGENTS=1
agentcreds[0]=""

if [[ -x "/usr/sfw/bin/gegrep" ]]; then
    GREP=/usr/sfw/bin/gegrep
else
    GREP=`which grep`
fi


ORAGCHOMELIST="/etc/oragchomelist"

if [[ ! -r $ORAGCHOMELIST ]]; then          # Solaris
    ORAGCHOMELIST="/var/opt/oracle/oragchomelist"
fi


OMS_HOME=`$GREP -i oms $ORAGCHOMELIST | xargs ls -d 2>/dev/null`

if [[ "$OMS_HOME" == "." ]]; then
    OMS_HOME=`cat $ORAGCHOMELIST | head -n 1`
fi

OMSORAINST="$OMS_HOME/oraInst.loc"
ORAINVENTORY=`$GREP inventory_loc $OMSORAINST | awk -F= '{print $2}'`
AGENT_HOME=`$GREP -vi REMOVED $ORAINVENTORY/ContentsXML/inventory.xml | $GREP "HOME NAME=\"agent13c" | awk '{print $3}' | sed -e 's/LOC=\"//' | sed -e 's/"//'`
AGENT_TARGETS_XML="$AGENT_HOME/../agent_inst/sysman/emd/targets.xml"
REPOS_DB_TARGET_NAME=`$GREP 'Member TYPE="oracle_database"' $AGENT_TARGETS_XML | sed 's/^.*NAME="//' | sed 's/".*$//'`


cat<<EOBANNER
Welcome to $0, version $VERSION, released $RELDATE.

Download the latest release of this script at any time from:
https://raw.githubusercontent.com/brianpardy/em13c/master/create_user_for_checksec13R2.sh

This script exists to supplement checksec13R2.sh and enable additional checks. When run, this
script will create a user named $OEM_USER in your EM13cR2 environment and give that user a 
random password, which gets printed to the screen at the end of the script. The script then
grants $OEM_USER VIEW_ANY_TARGET privilege, and then prompts you to supply the names of credentials
existing in your EM13cR2 environment. The script validates the names of credentials supplied, 
grants VIEW access to $OEM_USER for each credential, and assigns those credentials as preferred
credentials for $OEM_USER for each relevant target.

Providing credentials for the repository database enables the following additional checks in 
checksec13R2.sh:
	* Check for presence/absence of plugin bundle patches on all agents

Providing host credentials for every monitored host running an agent enables the following
additional checks in checksec13R2.sh:
	* Check for presence/absence of the latest Java version on all agents

Login to EMCLI as SYSMAN before running this script. If you already have an $OEM_USER account,
running this script will delete and recreate it with a new password.
EOBANNER

echo -ne "\nContinue? [y/n] "
read quitnow

if [[ "$quitnow" != "y" ]]; then
	echo -e "\nAborting.\n"
	exit 1
else
	echo -e "\nContinuing...\n\n"
fi

$EMCLI sync
NOT_LOGGED_IN=$?
if [[ $NOT_LOGGED_IN > 0 ]]; then
	echo "Login to EMCLI with \"$EMCLI login -username=SYSMAN\" then run this script again"
	exit 1
fi

$EMCLI delete_user -name=$OEM_USER -force
DELRET=$?
if [[ $DELRET > 0 ]]; then
	echo "Failed to delete existing $OEM_USER account, aborting."
	exit 1
else
	echo -e "\n"
fi



$EMCLI create_user -name=$OEM_USER -password="$OEM_USER_PW" -privilege="VIEW_ANY_TARGET" -privilege="CONNECT_TARGET;$REPOS_DB_TARGET_NAME:oracle_database" -privilege="CREATE_JOB" -privilege="DB_RUN_SQL;$REPOS_DB_TARGET_NAME:oracle_database" -role="EM_ALL_OPERATOR"
CREATERET=$?
if [[ $CREATERET > 0 ]]; then
	echo "Failed to create $OEM_USER account, aborting."
	exit 1
else
	echo -e "\n"
fi

echo -e "\nCreated user $OEM_USER with password: $OEM_USER_PW\n"

echo "Now $OEM_USER needs preferred credentials for the repository DB and repository DB host."
echo "Your repository DB target name is $REPOS_DB_TARGET_NAME"
echo -n "Enter the credential name for the repository DB Normal Database Credentials: "
read repodbnormcreds
echo -n "Enter the credential name for the repository DB SYSDBA Database Credentials: "
read reposysdbacreds
echo -n "Enter the credential name for the repository DB Database Host Credentials: "
read repodbhostcreds

echo -e "\nValidating that supplied credentials exist.\n"

### Check normal database credentials for repository
$EMCLI test_named_credential -cred_names="$repodbnormcreds" -target_name="$REPOS_DB_TARGET_NAME" -target_type=oracle_database
TESTRET=$?
if [[ $TESTRET != 0 ]]; then
	echo "Error: could not validate $repodbnormcreds against $REPOS_DB_TARGET_NAME, aborting."
	echo "Identify the correct credential name and run this script again."
	exit 1
fi

### Check sysdba database credentials for repository
$EMCLI test_named_credential -cred_names="$reposysdbacreds" -target_name="$REPOS_DB_TARGET_NAME" -target_type=oracle_database
TESTRET=$?
if [[ $TESTRET != 0 ]]; then
	echo "Error: could not validate $reposysdbacreds against $REPOS_DB_TARGET_NAME, aborting."
	echo "Identify the correct credential name and run this script again."
	exit 1
fi

### Check normal host credentials for repository
$EMCLI test_named_credential -cred_names="$repodbhostcreds" -target_name="$REPOS_DB_TARGET_NAME" -target_type=oracle_database
TESTRET=$?
if [[ $TESTRET != 0 ]]; then
	echo "Error: could not validate $repodbhostcreds against $REPOS_DB_TARGET_NAME, aborting."
	echo "Identify the correct credential name and run this script again."
	exit 1
fi


echo -e "\nGranting $OEM_USER GET_CREDENTIAL access to supplied credentials."

$EMCLI grant_privs -name=$OEM_USER -privilege="GET_CREDENTIAL;CRED_NAME=$repodbnormcreds" -privilege="GET_CREDENTIAL;CRED_NAME=$repodbhostcreds" -privilege="GET_CREDENTIAL;CRED_NAME=$reposysdbacreds"
GRANTRET=$?
if [[ $GRANTRET != 0 ]]; then
	echo "Error granting access to $repodbnormcreds and $repodbhostcreds"
	exit 1
fi

echo -e "\nConfirmed supplied credentials exist and granted to $OEM_USER.\n"
echo -e "\nThe next section asks you to supply credentials for the account used to run the Oracle Management Agent.\n"
echo -e "\nYou will receive a separate prompt for each agent. Enter 'done' (without quotes) to skip this step.\n"
echo -e "\nIf you provide these credentials, checksec13R2.sh can report on the Java version used by your agents.\n"

echo "Generating a list of all agent targets."
ALL_AGENTS=`$EMCLI get_targets | $GREP oracle_emd | awk '{print $4}'`

echo -e "Now loop through all agent targets and provide named credentials for the agent user account on each host.\n"

AGENTNUM=0

for currentagent in $ALL_AGENTS; do
	THEHOST=`echo $currentagent | sed -e 's/:.*$//'`
	(( AGENTNUM += 1 ))
	echo -ne "\nEnter the credential name to login as the agent user for $currentagent: "
	read curagentcred
	if [[ "$curagentcred" = "done" ]]; then
		echo "OK. Skipping this step."
		DOAGENTS=0
		break
	fi

	$EMCLI test_named_credential -cred_names="$curagentcred" -target_name="$THEHOST" -target_type=host
	TESTRET=$?
	if [[ $TESTRET != 0 ]]; then
		echo "Error: could not validate $curagentcred against $THEHOST, skipping agent credential configuration."
		DOAGENTS=0
		break
	fi

	$EMCLI grant_privs -name=$OEM_USER -privilege="GET_CREDENTIAL;CRED_NAME=$curagentcred"
	GRANTRET=$?
	if [[ $GRANTRET != 0 ]]; then
		echo "Error granting access to $curagentcred, skipping agent credential configuration."
		DOAGENTS=0
		break
	fi

	agentcreds[$AGENTNUM]=$curagentcred
done


echo -e "\nLogging out of EMCLI"
$EMCLI logout

echo -e "\nLogging in to EMCLI as $OEM_USER"
$EMCLI login -username=$OEM_USER -password=$OEM_USER_PW
LOGINRET=$?
if [[ $LOGINRET != 0 ]]; then
	echo "EMCLI login as $OEM_USER failed.  Aborting."
	exit 1
else
	echo -e "\n"
fi

echo "Setting preferred credentials $repodbnormcreds for $OEM_USER on $REPOS_DB_TARGET_NAME"
$EMCLI set_preferred_credential -set_name="DBCredsNormal" -target_name="$REPOS_DB_TARGET_NAME" -target_type="oracle_database" -credential_name="$repodbnormcreds" -credential_owner="$OEM_CREDENTIAL_OWNER"
SETRET=$?
if [[ $SETRET != 0 ]]; then
	echo "Error setting preferred credential $repodbnormcreds for $OEM_USER on $REPOS_DB_TARGET_NAME"
	exit 1
else
	echo -e "\n"
fi

echo "Setting preferred credentials $reposysdbacreds for $OEM_USER on $REPOS_DB_TARGET_NAME"
$EMCLI set_preferred_credential -set_name="DBCredsSYSDBA" -target_name="$REPOS_DB_TARGET_NAME" -target_type="oracle_database" -credential_name="$reposysdbacreds" -credential_owner="$OEM_CREDENTIAL_OWNER"
SETRET=$?
if [[ $SETRET != 0 ]]; then
	echo "Error setting preferred credential $reposysdbacreds for $OEM_USER on $REPOS_DB_TARGET_NAME"
	exit 1
else
	echo -e "\n"
fi

echo "Setting preferred credentials $repodbhostcreds for $OEM_USER on $REPOS_DB_TARGET_NAME"
$EMCLI set_preferred_credential -set_name="DBHostCreds" -target_name="$REPOS_DB_TARGET_NAME" -target_type="oracle_database" -credential_name="$repodbhostcreds" -credential_owner="$OEM_CREDENTIAL_OWNER"
SETRET=$?
if [[ $SETRET != 0 ]]; then
	echo "Error setting preferred credential $repodbhostcreds for $OEM_USER on $REPOS_DB_TARGET_NAME"
	exit 1
else
	echo -e "\n"
fi


if [[ $DOAGENTS == 1 ]]; then
	echo -e "\nNow assigning preferred credentials for agent targets."
	AGENTNUM=0
	for currentagent in $ALL_AGENTS; do
		(( AGENTNUM += 1 ))
		THEHOST=`echo $currentagent | sed -e 's/:.*$//'`
		echo -e "\nSetting preferred credentials for $OEM_USER on $currentagent"
		$EMCLI set_preferred_credential -set_name="HostCredsNormal" -target_name=$THEHOST -target_type="host" -credential_name="${agentcreds[$AGENTNUM]}" -credential_owner="$OEM_CREDENTIAL_OWNER"
		SETRET=$?
		if [[ $SETRET != 0 ]]; then
			echo "Error setting preferred credential ${agentcreds[$AGENTNUM]} for $OEM_USER on $THEHOST"
		else
			echo -e "\n"
		fi
	done
fi

echo -e "\n\nAll finished. User $OEM_USER now logged in to EMCLI.\n\nNow go run the checksec13R2.sh script."
echo -e "\n\nAs a reminder, user $OEM_USER has password $OEM_USER_PW."
