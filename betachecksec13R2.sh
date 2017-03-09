#!/bin/bash
#
# This script should examine your EM13c environment, identify the ports
# each component uses, and check for usage of encryption protocols older
# then TLSv1.2, as well as make sure that weak and medium strength 
# cipher suites get rejected.  It will also validate your system comparing
# against the latest recommended patches and also flags the use of demo 
# or self-signed certificates. 
#
# Released  v0.1:  Initial beta release 5 Apr 2016
# Changes   v0.2:  Updated for current patches
# Changes   v0.3:  APR2016 patchset added
# Changes   v0.4:  Plugin updates for 20160429
# Changes   v0.5:  Plugin updates for 20160531
# Changes   v0.6:  Plugin/OMS/DB updates for 20160719 CPU + Java check
# Changes   v0.7:  Plugin/OMS updates for 20160816 bundles
#                  Support for SLES11 OpenSSL 1 parallel package
#                  Add checks for TLSv1.1, TLSv1.2 
#                  Permit only TLSv1.2 where supported by OpenSSL
# Changes   v0.8:  Fix broken check for SSL_CIPHER_SUITES
#                  Add checks for ENCRYPTION_SERVER, ENCRYPTION_CLIENT,
#                  CRYPTO_CHECKSUM_SERVER, CRYPTO_CHECKSUM_CLIENT,
#                  ENCRYPTION_TYPES_SERVER, ENCRYPTION_TYPES_CLIENT,
#                  CRYPTO_CHECKSUM_TYPES_SERVER, CRYPTO_CHECKSUM_TYPES_CLIENT
# Changes   v0.9:  Plugin updates for 20160920
#                  Support TLSv1.2 when available in certcheck,
#                  democertcheck, and ciphercheck
# Changes   v1.0:  Converted to EM13cR2, converted repository DB checks
#                  to use DBBP Bundle Patch (aka Exadata patch), not PSU
# Changes   v1.1:  Updated for 20161231 EM13cR2 patches. 
#                  Updated for 20170117 security patches.
#                  Add check for OPatch and OMSPatcher versions. 
# Changes   v1.2:  Updated for 20170131 bundle patches.
# Changes   v1.3:  Updated for 20170228 bundle patches.
# Changes   v1.4:  Added patches 25604219 and 24327938
#                  Updated Java check to 1.7.0_131
# Changes   v1.5:  Add check for chained agent Java version
# Changes   v1.6:  Updated note references.
#                  Added plugin patch checks for OMS chained agent
#                  for non-default discovery/monitoring plugins
#                  not previously checked. If you do not have
#                  those plugins installed, the script will not
#                  indicate failure due to the missing patch.
#                  Added EMCLI check. If you login to EMCLI
#                  before running ./checksec13R2.sh, the script
#                  will soon check additional items using EMCLI.
# Changes   v2.0:  Now checking plugin bundle patches on all agents.
#                  Requires EMCLI.  Run the script while not logged in
#                  to EMCLI for instructions.  Login to EMCLI and run
#                  the script to use the new functionality.
#
# From: @BrianPardy on Twitter
#
# Known functional on Linux x86-64, may work on Solaris and AIX.
#
# Run this script as the Oracle EM13c software owner, with your environment
# fully up and running.
#
# Thanks to Dave Corsar, who tested a previous version on Solaris and 
# let me know the changes needed to make the script work on Solaris.
#
# Thanks to opa tropa who confirmed AIX functionality on a previous
# version and noted the use of GNU extensions to grep, which I have 
# since removed.
#
# Thanks to Bob Schuppin who noted the use of TLS1 when using
# openssl to check ciphers/certificates/demo-certs, which I have
# now fixed.
#
# Thanks to Paige, who informed me of a broken check for the 
# SSL_CIPHER_SUITES parameter that led me to add the additional checks
# for SQL*Net encryption
#
# In order to check selections for ENCRYPTION_TYPES and CRYPTO_CHECKSUM_TYPES
# I have to make some judgement calls. Due to MD5's known issues, I consider
# it unacceptable for CRYPTO_CHECKSUM_TYPES. Unfortunately SHA256, the
# best choice available, can cause problems with target promotion in OEM
# (see MOS note 2167682.1) so this check will simply make sure you do not
# permit MD5, but will not enforce SHA256. This same issue also requires
# allowing 3DES168 as an encryption algorithm to promote targets, though
# I would generally not allow 3DES168 for security reasons. This check
# will simply make sure you do not permit DES, DES40, 3DES112, or any
# of the RC4_* algorithms.
#
# As of version 2.0, this script will now make use of EMCLI if the user
# executing it has logged in to EMCLI before executing the script.
#
# To make use of this new functionality, you must perform the following steps
# before running the script:
#
# - Login to EMCLI using an OEM user account
# - Make sure the OEM user account has specified default normal database
#   credentials and default host credentials for the repository database
#   target.
#
# 
# Dedicated to our two Lhasa Apsos:
#   Lucy (6/13/1998 - 3/13/2015)
#   Ethel (6/13/1998 - 7/31/2015)
# 

SCRIPTNAME=`basename $0`
PATCHDATE="28 Feb 2017"
PATCHNOTE="1664074.1, 2219797.1"
OMSHOST=`hostname -f`
VERSION="2.0"
FAIL_COUNT=0
FAIL_TESTS=""

RUN_DB_CHECK=0
VERBOSE_CHECKSEC=2
EMCLI_CHECK=0

HOST_OS=`uname -s`
HOST_ARCH=`uname -m`

ORAGCHOMELIST="/etc/oragchomelist"
ORATAB="/etc/oratab"
OPENSSL=`which openssl`

if [[ -x "/usr/bin/openssl1" && -f "/etc/SuSE-release" ]]; then
	OPENSSL=`which openssl1`
fi

if [[ ! -r $ORAGCHOMELIST ]]; then			# Solaris
	ORAGCHOMELIST="/var/opt/oracle/oragchomelist"
fi

if [[ ! -r $ORATAB ]]; then 				# Solaris
	ORATAB="/var/opt/oracle/oratab"
fi

if [[ -x "/usr/sfw/bin/gegrep" ]]; then
	GREP=/usr/sfw/bin/gegrep
else
	GREP=`which grep`
fi

OPENSSL_HAS_TLS1_1=`$OPENSSL s_client help 2>&1 | $GREP -c tls1_1`
OPENSSL_HAS_TLS1_2=`$OPENSSL s_client help 2>&1 | $GREP -c tls1_2`
OPENSSL_ALLOW_TLS1_2_ONLY=$OPENSSL_HAS_TLS1_2

OPENSSL_PERMIT_FORBID_NON_TLS1_2="Permit"

if [[ $OPENSSL_ALLOW_TLS1_2_ONLY -gt 0 ]]; then
	OPENSSL_PERMIT_FORBID_NON_TLS1_2="Forbid"
fi

OMS_HOME=`$GREP -i oms $ORAGCHOMELIST | xargs ls -d 2>/dev/null`

if [[ "$OMS_HOME" == "." ]]; then
	OMS_HOME=`cat $ORAGCHOMELIST | head -n 1`
fi


OPATCH="$OMS_HOME/OPatch/opatch"
OPATCHAUTO="$OMS_HOME/OPatch/opatchauto"
OMSPATCHER="$OMS_HOME/OMSPatcher/omspatcher"
OMSORAINST="$OMS_HOME/oraInst.loc"
ORAINVENTORY=`$GREP inventory_loc $OMSORAINST | awk -F= '{print $2}'`

MW_HOME=$OMS_HOME
COMMON_HOME="$MW_HOME/oracle_common"

AGENT_HOME=`$GREP -vi REMOVED $ORAINVENTORY/ContentsXML/inventory.xml | $GREP "HOME NAME=\"agent13c" | awk '{print $3}' | sed -e 's/LOC=\"//' | sed -e 's/"//'`
AGENT_TARGETS_XML="$AGENT_HOME/../agent_inst/sysman/emd/targets.xml"
REPOS_DB_TARGET_NAME=`$GREP 'Member TYPE="oracle_database"' $AGENT_TARGETS_XML | sed 's/^.*NAME="//' | sed 's/".*$//'`


EM_INSTANCE_BASE=`$GREP GCDomain $MW_HOME/domain-registry.xml | sed -e 's/.*=//' | sed -e 's/\/user_projects.*$//' | sed -e 's/"//'`

EMGC_PROPS="$EM_INSTANCE_BASE/em/EMGC_OMS1/emgc.properties"
EMBIP_PROPS="$EM_INSTANCE_BASE/em/EMGC_OMS1/embip.properties"
#OHS_ADMIN_CONF="$EM_INSTANCE_BASE/WebTierIH1/config/OHS/ohs1/admin.conf"

PORT_UPL=`$GREP EM_UPLOAD_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_OMS=`$GREP EM_CONSOLE_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_OMS_JAVA=`$GREP MS_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_NODEMANAGER=`$GREP EM_NODEMGR_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_BIP=`$GREP BIP_HTTPS_PORT $EMBIP_PROPS | awk -F= '{print $2}'`
PORT_BIP_OHS=`$GREP BIP_HTTPS_OHS_PORT $EMBIP_PROPS | awk -F= '{print $2}'`
PORT_ADMINSERVER=`$GREP AS_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
#PORT_OHS_ADMIN=`$GREP Listen $OHS_ADMIN_CONF | awk '{print $2}'`
PORT_AGENT=`$AGENT_HOME/bin/emctl status agent | $GREP 'Agent URL' | sed -e 's/\/emd\/main\///' | sed -e 's/^.*://' | uniq`

REPOS_DB_CONNDESC=`$GREP EM_REPOS_CONNECTDESCRIPTOR $EMGC_PROPS | sed -e 's/EM_REPOS_CONNECTDESCRIPTOR=//' | sed -e 's/\\\\//g'`
REPOS_DB_HOST=`echo $REPOS_DB_CONNDESC | sed -e 's/^.*HOST=//' | sed -e 's/).*$//'`
REPOS_DB_SID=`echo $REPOS_DB_CONNDESC | sed -e 's/^.*SID=//' | sed -e 's/).*$//'`

if [[ "$REPOS_DB_HOST" == "$OMSHOST" ]]; then
	REPOS_DB_HOME=`$GREP "$REPOS_DB_SID:" $ORATAB | awk -F: '{print $2}'`
	REPOS_DB_VERSION=`$REPOS_DB_HOME/OPatch/opatch lsinventory -oh $REPOS_DB_HOME | $GREP 'Oracle Database' | awk '{print $4}'`

	if [[ "$REPOS_DB_VERSION" == "11.2.0.4.0" ]]; then
		RUN_DB_CHECK=1
	fi

	if [[ "$REPOS_DB_VERSION" == "12.1.0.2.0" ]]; then
		RUN_DB_CHECK=1
	fi

	if [[ "$RUN_DB_CHECK" -eq 0 ]]; then
		echo -e "\tSkipping local repository DB patch check, only 11.2.0.4 or 12.1.0.2 supported by this script for now"
	fi
fi

EMCLI="$MW_HOME/bin/emcli"
$EMCLI sync
EMCLI_NOT_LOGGED_IN=$?

if [[ "$EMCLI_NOT_LOGGED_IN" -eq 0 ]]; then
    EMCLI_CHECK=1
fi


patchercheck () {
	PATCHER_CHECK_COMPONENT=$1
	PATCHER_CHECK_OH=$2
	PATCHER_CHECK_VERSION=$3

	if [[ $PATCHER_CHECK_COMPONENT == "OPatch" ]]; then
		PATCHER_RET=`$PATCHER_CHECK_OH/opatch version -jre $MW_HOME/oracle_common/jdk | grep Version | sed 's/.*: //'`
		PATCHER_MINVER=`echo -e ${PATCHER_RET}\\\\n${PATCHER_CHECK_VERSION} | sort -t. -g | head -n 1`

		if [[ $PATCHER_MINVER == $PATCHER_CHECK_VERSION ]]; then
			echo OK
		else
			echo FAILED
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$PATCHER_CHECK_COMPONENT @ $PATCHER_CHECK_OH: fails minimum version requirement $PATCHER_MINVER vs $PATCHER_CHECK_VERSION"
		fi
		return
	fi

	if [[ $PATCHER_CHECK_COMPONENT == "OMSPatcher" ]]; then
		PATCHER_RET=`$PATCHER_CHECK_OH/omspatcher version -jre $MW_HOME/oracle_common/jdk | grep 'OMSPatcher Version' | sed 's/.*: //'`
		PATCHER_MINVER=`echo -e ${PATCHER_RET}\\\\n${PATCHER_CHECK_VERSION} | sort -t. -g | head -n 1`

		if [[ $PATCHER_MINVER == $PATCHER_CHECK_VERSION ]]; then
			echo OK
		else
			echo FAILED
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$PATCHER_CHECK_COMPONENT @ $PATCHER_CHECK_OH: fails minimum version requirement $PATCHER_MINVER vs $PATCHER_CHECK_VERSION"
		fi
		return
	fi
}



sslcheck () {
	OPENSSL_CHECK_COMPONENT=$1
	OPENSSL_CHECK_HOST=$2
	OPENSSL_CHECK_PORT=$3
	OPENSSL_CHECK_PROTO=$4
	OPENSSL_AVAILABLE_OR_DISABLED="disabled"

	if [[ $OPENSSL_CHECK_PROTO == "tls1_1" && $OPENSSL_HAS_TLS1_1 == 0 ]]; then
		echo -en "\tYour OpenSSL ($OPENSSL) does not support $OPENSSL_CHECK_PROTO. Skipping $OPENSSL_CHECK_COMPONENT\n"
		return
	fi

	if [[ $OPENSSL_CHECK_PROTO == "tls1_2" && $OPENSSL_HAS_TLS1_2 == 0 ]]; then
		echo -en "\tYour OpenSSL ($OPENSSL) does not support $OPENSSL_CHECK_PROTO. Skipping $OPENSSL_CHECK_COMPONENT\n"
		return
	fi


	OPENSSL_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$OPENSSL_CHECK_PROTO 2>&1 | $GREP Cipher | $GREP -c 0000`
	

	if [[ $OPENSSL_CHECK_PROTO == "tls1" || $OPENSSL_CHECK_PROTO == "tls1_1" || $OPENSSL_CHECK_PROTO == "tls1_2" ]]; then

		if [[ $OPENSSL_ALLOW_TLS1_2_ONLY > 0 ]]; then
			if [[ $OPENSSL_CHECK_PROTO == "tls1_2" ]]; then
				OPENSSL_AVAILABLE_OR_DISABLED="available"
			fi
		fi

		if [[ $OPENSSL_ALLOW_TLS1_2_ONLY == 0 ]]; then
			OPENSSL_AVAILABLE_OR_DISABLED="available"
		fi

		echo -en "\tConfirming $OPENSSL_CHECK_PROTO $OPENSSL_AVAILABLE_OR_DISABLED for $OPENSSL_CHECK_COMPONENT at $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT... "

		if [[ $OPENSSL_AVAILABLE_OR_DISABLED == "available" ]]; then
			if [[ $OPENSSL_RETURN -eq "0" ]]; then
				echo OK
			else
				echo FAILED
				FAIL_COUNT=$((FAIL_COUNT+1))
				FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:$OPENSSL_CHECK_PROTO protocol connection failed"
			fi
		fi

		if [[ $OPENSSL_AVAILABLE_OR_DISABLED == "disabled" ]]; then
			if [[ $OPENSSL_RETURN -ne "0" ]]; then
				echo OK
			else
				echo FAILED
				FAIL_COUNT=$((FAIL_COUNT+1))
				FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:$OPENSSL_CHECK_PROTO protocol connection allowed"
			fi
		fi


	fi

	if [[ $OPENSSL_CHECK_PROTO == "ssl2" || $OPENSSL_CHECK_PROTO == "ssl3" ]]; then
		echo -en "\tConfirming $OPENSSL_CHECK_PROTO $OPENSSL_AVAILABLE_OR_DISABLED for $OPENSSL_CHECK_COMPONENT at $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT... "
		if [[ $OPENSSL_RETURN -ne "0" ]]; then
			echo OK
		else
			echo FAILED
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:$OPENSSL_CHECK_PROTO protocol connection succeeded"
		fi
	fi
}

opatchcheck () {
	OPATCH_CHECK_COMPONENT=$1
	OPATCH_CHECK_OH=$2
	OPATCH_CHECK_PATCH=$3

	if [[ "$OPATCH_CHECK_COMPONENT" == "ReposDBHome" ]]; then
		OPATCH_RET=`$OPATCH_CHECK_OH/OPatch/opatch lsinv -oh $OPATCH_CHECK_OH | $GREP $OPATCH_CHECK_PATCH`
	else
		OPATCH_RET=`$OPATCH lsinv -oh $OPATCH_CHECK_OH | $GREP $OPATCH_CHECK_PATCH`
	fi

	if [[ -z "$OPATCH_RET" ]]; then
		echo FAILED
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPATCH_CHECK_COMPONENT @ ${OPATCH_CHECK_OH}:Patch $OPATCH_CHECK_PATCH not found"
	else
		echo OK
	fi

	test $VERBOSE_CHECKSEC -ge 2 && echo $OPATCH_RET

}

opatchplugincheck () {
	OPATCH_CHECK_COMPONENT=$1
	OPATCH_CHECK_OH=$2
	OPATCH_CHECK_PATCH=$3
    OPATCH_PLUGIN_DIR=$4

    if [[ -d "${OPATCH_CHECK_OH}/plugins/${OPATCH_PLUGIN_DIR}" ]]; then
        if [[ "$OPATCH_CHECK_COMPONENT" == "ReposDBHome" ]]; then
            OPATCH_RET=`$OPATCH_CHECK_OH/OPatch/opatch lsinv -oh $OPATCH_CHECK_OH | $GREP $OPATCH_CHECK_PATCH`
        else
            OPATCH_RET=`$OPATCH lsinv -oh $OPATCH_CHECK_OH | $GREP $OPATCH_CHECK_PATCH`
        fi
    else
            OPATCH_RET="Plugin dir $OPATCH_PLUGIN_DIR does not exist, not installed"
    fi

	if [[ -z "$OPATCH_RET" ]]; then
		echo FAILED
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPATCH_CHECK_COMPONENT @ ${OPATCH_CHECK_OH}:Patch $OPATCH_CHECK_PATCH not found"
	else
		echo OK
	fi

	test $VERBOSE_CHECKSEC -ge 2 && echo $OPATCH_RET
}

opatchautocheck () {
	OPATCHAUTO_CHECK_COMPONENT=$1
	OPATCHAUTO_CHECK_OH=$2
	OPATCHAUTO_CHECK_PATCH=$3

	OPATCHAUTO_RET=`$OPATCHAUTO lspatches -oh $OPATCHAUTO_CHECK_OH | $GREP $OPATCHAUTO_CHECK_PATCH`

	if [[ -z "$OPATCHAUTO_RET" ]]; then
		echo FAILED
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPATCHAUTO_CHECK_COMPONENT @ ${OPATCHAUTO_CHECK_OH}:Patch $OPATCHAUTO_CHECK_PATCH not found"
	else
		echo OK
	fi

	test $VERBOSE_CHECKSEC -ge 2 && echo $OPATCHAUTO_RET

}

omspatchercheck () {
	OMSPATCHER_CHECK_COMPONENT=$1
	OMSPATCHER_CHECK_OH=$2
	OMSPATCHER_CHECK_PATCH=$3

	OMSPATCHER_RET=`$OMSPATCHER lspatches -oh $OMSPATCHER_CHECK_OH | $GREP $OMSPATCHER_CHECK_PATCH`

	if [[ -z "$OMSPATCHER_RET" ]]; then
		echo FAILED
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OMSPATCHER_CHECK_COMPONENT @ ${OMSPATCHER_CHECK_OH}:Patch $OMSPATCHER_CHECK_PATCH not found"
	else
		echo OK
	fi

	test $VERBOSE_CHECKSEC -ge 2 && echo $OMSPATCHER_RET

}

certcheck () {
	CERTCHECK_CHECK_COMPONENT=$1
	CERTCHECK_CHECK_HOST=$2
	CERTCHECK_CHECK_PORT=$3

	CERTCHECK_PROTOCOL="tls1"
	if [[ $OPENSSL_ALLOW_TLS1_2_ONLY > 0 ]]; then
		CERTCHECK_PROTOCOL=tls1_2
	fi

	echo -ne "\tChecking certificate at $CERTCHECK_CHECK_COMPONENT ($CERTCHECK_CHECK_HOST:$CERTCHECK_CHECK_PORT, protocol $CERTCHECK_PROTOCOL)... "


	OPENSSL_SELFSIGNED_COUNT=`echo Q | $OPENSSL s_client -prexit -connect $CERTCHECK_CHECK_HOST:$CERTCHECK_CHECK_PORT -$CERTCHECK_PROTOCOL 2>&1 | $GREP -ci "self signed certificate"`

	if [[ $OPENSSL_SELFSIGNED_COUNT -eq "0" ]]; then
		echo OK
	else
		echo FAILED - Found self-signed certificate
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$CERTCHECK_CHECK_COMPONENT @ ${CERTCHECK_CHECK_HOST}:${CERTCHECK_CHECK_PORT} found self-signed certificate"
	fi
}

democertcheck () {
	DEMOCERTCHECK_CHECK_COMPONENT=$1
	DEMOCERTCHECK_CHECK_HOST=$2
	DEMOCERTCHECK_CHECK_PORT=$3

	DEMOCERTCHECK_PROTOCOL="tls1"
	if [[ $OPENSSL_ALLOW_TLS1_2_ONLY > 0 ]]; then
		DEMOCERTCHECK_PROTOCOL=tls1_2
	fi

	echo -ne "\tChecking demo certificate at $DEMOCERTCHECK_CHECK_COMPONENT ($DEMOCERTCHECK_CHECK_HOST:$DEMOCERTCHECK_CHECK_PORT, protocol $DEMOCERTCHECK_PROTOCOL)... "

	OPENSSL_DEMO_COUNT=`echo Q | $OPENSSL s_client -prexit -connect $DEMOCERTCHECK_CHECK_HOST:$DEMOCERTCHECK_CHECK_PORT -$CERTCHECK_PROTOCOL 2>&1 | $GREP -ci "issuer=/C=US/ST=MyState/L=MyTown/O=MyOrganization/OU=FOR TESTING ONLY/CN"`

	if [[ $OPENSSL_DEMO_COUNT -eq "0" ]]; then
		echo OK
	else
		echo FAILED - Found demonstration certificate
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$DEMOCERTCHECK_CHECK_COMPONENT @ ${DEMOCERTCHECK_CHECK_HOST}:${DEMOCERTCHECK_CHECK_PORT} found demonstration certificate"
	fi
}


ciphercheck () {
	OPENSSL_CHECK_COMPONENT=$1
	OPENSSL_CHECK_HOST=$2
	OPENSSL_CHECK_PORT=$3

	CIPHERCHECK_PROTOCOL="tls1"
	if [[ $OPENSSL_ALLOW_TLS1_2_ONLY > 0 ]]; then
		CIPHERCHECK_PROTOCOL=tls1_2
	fi

	echo -ne "\tChecking LOW strength ciphers on $OPENSSL_CHECK_COMPONENT ($OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT, protocol $CIPHERCHECK_PROTOCOL)..."

	OPENSSL_LOW_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$CIPHERCHECK_PROTOCOL -cipher LOW 2>&1 | $GREP Cipher | uniq | $GREP -c 0000`

	if [[ $OPENSSL_LOW_RETURN -eq "0" ]]; then
		echo -e "\tFAILED - PERMITS LOW STRENGTH CIPHER CONNECTIONS"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Permits LOW strength ciphers"
	else
		echo -e "\tOK"
	fi


	echo -ne "\tChecking MEDIUM strength ciphers on $OPENSSL_CHECK_COMPONENT ($OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT)..."

	OPENSSL_MEDIUM_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$CIPHERCHECK_PROTOCOL -cipher MEDIUM 2>&1 | $GREP Cipher | uniq | $GREP -c 0000`

	if [[ $OPENSSL_MEDIUM_RETURN -eq "0" ]]; then
		echo -e "\tFAILED - PERMITS MEDIUM STRENGTH CIPHER CONNECTIONS"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Permits MEDIUM strength ciphers"
	else
		echo -e "\tOK"
	fi



	echo -ne "\tChecking HIGH strength ciphers on $OPENSSL_CHECK_COMPONENT ($OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT)..."

	OPENSSL_HIGH_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$CIPHERCHECK_PROTOCOL -cipher HIGH 2>&1 | $GREP Cipher | uniq | $GREP -c 0000`

	if [[ $OPENSSL_HIGH_RETURN -eq "0" ]]; then
		echo -e "\tOK"
	else
		echo -e "\tFAILED - CANNOT CONNECT WITH HIGH STRENGTH CIPHER"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Rejects HIGH strength ciphers"
	fi
	echo
}

wlspatchcheck () {
	WLSDIR=$1
	WLSPATCH=$2

	WLSCHECK_RETURN=`( cd $MW_HOME/utils/bsu && $MW_HOME/utils/bsu/bsu.sh -report ) | $GREP $WLSPATCH`
	WLSCHECK_COUNT=`echo $WLSCHECK_RETURN | wc -l`

	if [[ $WLSCHECK_COUNT -ge "1" ]]; then
		echo -e "\tOK"
	else
		echo -e "\tFAILED - PATCH NOT FOUND"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WLSDIR:Patch $WLSPATCH not found"
	fi

	test $VERBOSE_CHECKSEC -ge 2 && echo $WLSCHECK_RETURN
	
}

javacheck () {
	WHICH_JAVA=$1
	JAVA_DIR=$2

	JAVACHECK_RETURN=`$JAVA_DIR/bin/java -version 2>&1 | $GREP version | awk '{print $3}' | sed -e 's/"//g'`

	if [[ "$JAVACHECK_RETURN" == "1.7.0_131" ]]; then
		echo -e "\tOK"
	else
		#echo -e "\tFAILED - Found version $JAVACHECK_RETURN"
		echo -e "\tFAILED"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_JAVA Java in ${JAVA_DIR}:Found incorrect version $JAVACHECK_RETURN"
	fi
	test $VERBOSE_CHECKSEC -ge 2 && echo $JAVACHECK_RETURN
}

emclicheck () {
    WHICH_TARGET_TYPE=$1
    WHICH_PLUGIN=$2
    WHICH_PLUGIN_TYPE=$3
    WHICH_PLUGIN_VERSION=$4
    WHICH_PATCH=$5
    EMCLICHECK_LABEL=$6
    EMCLICHECK_PATCH_DESC=$7

    ALL_AGENTS=`$EMCLI get_targets | $GREP oracle_emd | awk '{print $4}'`

    for i in $ALL_AGENTS; do
        EMCLICHECK_RETURN="FAILED"
        EMCLICHECK_FOUND_VERSION=0
        EMCLICHECK_QUERY_RET=0

        echo -ne "\n\t($EMCLICHECK_LABEL) $EMCLICHECK_PATCH_DESC @ $i ($WHICH_PATCH)... "

        EMCLICHECK_INITIAL_RETURN=`$EMCLI list_plugins_on_agent -agent_names="$i" -include_discovery | $GREP $WHICH_PLUGIN | sed "s/^.*$WHICH_PLUGIN/$WHICH_PLUGIN/"`

        if [[ -z "$EMCLICHECK_INITIAL_RETURN" ]]; then
            echo "OK - plugin not installed"
        else
            if [[ "$WHICH_PLUGIN_TYPE" == "discovery" ]]; then
                CUR_PLUGIN_VERSION="${WHICH_PLUGIN_VERSION}\*"
            else
                CUR_PLUGIN_VERSION="${WHICH_PLUGIN_VERSION}$"
            fi

            for j in $EMCLICHECK_INITIAL_RETURN; do
                EMCLICHECK_FOUND_VERSION=`echo $j | $GREP -c $CUR_PLUGIN_VERSION`
                if [[ $EMCLICHECK_FOUND_VERSION > 0 ]]; then
                    EMCLICHECK_RETURN="OK"
                    break
                fi
            done

            # OK at this point simply means plugin home exists on the agent, still need to check for the requested patch

            #if [[ "$EMCLICHECK_RETURN" != "OK" ]]; then
            #    echo -e "\tOK - plugin not installed"
            #fi

            # Now check for existence of patch

            if [[ "$EMCLICHECK_RETURN" == "OK" ]]; then
                EMCLICHECK_QUERY_RET=`$EMCLI execute_sql -targets="${REPOS_DB_TARGET_NAME}:oracle_database" -sql="select 'PATCH_INSTALLED' from sysman.mgmt\\\$applied_patches where patch = $WHICH_PATCH and host = (select host_name from sysman.mgmt\\\$target where target_name = '$i')" | $GREP -c PATCH_INSTALLED`

                if [[ "$EMCLICHECK_QUERY_RET" -eq 1 ]]; then
                    echo -e "\tOK"
                else
                    echo -e "\tFAILED"
                    FAIL_COUNT=$((FAIL_COUNT+1))
                    FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PATCH missing in $WHICH_PLUGIN on $i"
                fi
            else
                echo -e "\tOK - plugin not installed"
            fi
        fi

#        test $VERBOSE_CHECKSEC -ge 2 && echo $EMCLICHECK_RETURN
    done
}


paramcheck () {
	WHICH_PARAM=$1
	WHICH_ORACLE_HOME=$2
	WHICH_FILE=$3

	PARAMCHECK_PARAM_FOUND=`$GREP $WHICH_PARAM $WHICH_ORACLE_HOME/network/admin/$WHICH_FILE | $GREP -v '^#' | wc -l`

	if [[ $PARAMCHECK_PARAM_FOUND == "0" ]]; then
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:parameter not found"
		return
	fi

	PARAMCHECK_RETURN=`$GREP $WHICH_PARAM $WHICH_ORACLE_HOME/network/admin/$WHICH_FILE | $GREP -v '^#'  | awk -F= '{print $2}' | sed -e 's/\s//g'`
	if [[ "$WHICH_PARAM" == "SSL_VERSION" ]]; then
		if [[ "$PARAMCHECK_RETURN" == "1.0" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SSL_CIPHER_SUITES" ]]; then
		if [[ "$PARAMCHECK_RETURN" == "(SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA)" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.ENCRYPTION_SERVER" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE '(requested|required)' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "0" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.ENCRYPTION_CLIENT" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE '(requested|required)' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "0" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.CRYPTO_CHECKSUM_SERVER" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE '(requested|required)' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "0" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.CRYPTO_CHECKSUM_CLIENT" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE '(requested|required)' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "0" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE 'MD5' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "1" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value (do not use MD5, only use SHA1 and/or SHA256)"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE 'MD5' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "1" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value (do not use MD5, only use SHA1 and/or SHA256)"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.ENCRYPTION_TYPES_SERVER" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE '([(,]des[),]|3des112|rc4|des40)' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "1" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value (do not use DES, DES40, RC4_40, RC4_56, RC4_128, RC4_256, or 3DES112)"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi

	if [[ "$WHICH_PARAM" == "SQLNET.ENCRYPTION_TYPES_CLIENT" ]]; then
		echo $PARAMCHECK_RETURN | $GREP -iE '([(,]des[),]|3des112|rc4|des40)' >& /dev/null
		PARAM_STATE=$?

		if [[ $PARAM_STATE == "1" ]]; then
			echo -e "OK"
		else
			echo -e "FAILED - Found $WHICH_PARAM = $PARAMCHECK_RETURN"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PARAM in $WHICH_FILE for home ${WHICH_ORACLE_HOME}:incorrect parameter value (do not use DES, DES40, RC4_40, RC4_56, RC4_128, RC4_256, or 3DES112)"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $PARAMCHECK_RETURN
	fi
}


### MAIN SCRIPT HERE


echo -e "Performing EM13c R2 security checkup version $VERSION on $OMSHOST at `date`.\n"

echo "Using port definitions from configuration files "
echo -e "\t/etc/oragchomelist"
echo -e "\t$EMGC_PROPS"
echo -e "\t$EMBIP_PROPS"
echo -e "\t$AGENT_TARGETS_XML"
echo
echo -e "\tAgent port found at $OMSHOST:$PORT_AGENT"
echo -e "\tBIPublisher port found at $OMSHOST:$PORT_BIP"
echo -e "\tBIPublisherOHS port found at $OMSHOST:$PORT_BIP_OHS"
echo -e "\tNodeManager port found at $OMSHOST:$PORT_NODEMANAGER"
echo -e "\tOMSconsole port found at $OMSHOST:$PORT_OMS"
echo -e "\tOMSproxy port found at $OMSHOST:$PORT_OMS_JAVA"
echo -e "\tOMSupload port found at $OMSHOST:$PORT_UPL"
echo -e "\tWLSadmin found at $OMSHOST:$PORT_ADMINSERVER"
echo
echo -e "\tRepository DB version=$REPOS_DB_VERSION SID=$REPOS_DB_SID host=$REPOS_DB_HOST"
echo -e "\tRepository DB target name=$REPOS_DB_TARGET_NAME"
echo 
echo -e "\tUsing OPENSSL=$OPENSSL (has TLS1_2=$OPENSSL_HAS_TLS1_2)"

if [[ $RUN_DB_CHECK -eq "1" ]]; then
	echo -e "\tRepository DB on OMS server, will check patches/parameters in $REPOS_DB_HOME"
fi

echo -e "\n(1) Checking SSL/TLS configuration (see notes 2138391.1, 2212006.1)"

echo -e "\n\t(1a) Forbid SSLv2 connections"
sslcheck Agent $OMSHOST $PORT_AGENT ssl2
sslcheck BIPublisher $OMSHOST $PORT_BIP ssl2
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER ssl2
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS ssl2
sslcheck OMSconsole $OMSHOST $PORT_OMS ssl2
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA ssl2
sslcheck OMSupload $OMSHOST $PORT_UPL ssl2
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER ssl2

echo -e "\n\t(1b) Forbid SSLv3 connections"
sslcheck Agent $OMSHOST $PORT_AGENT ssl3
sslcheck BIPublisher $OMSHOST $PORT_BIP ssl3
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER ssl3
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS ssl3
sslcheck OMSconsole $OMSHOST $PORT_OMS ssl3
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA ssl3
sslcheck OMSupload $OMSHOST $PORT_UPL ssl3
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER ssl3

echo -e "\n\t(1c) $OPENSSL_PERMIT_FORBID_NON_TLS1_2 TLSv1 connections"
sslcheck Agent $OMSHOST $PORT_AGENT tls1
sslcheck BIPublisher $OMSHOST $PORT_BIP tls1
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER tls1
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS tls1
sslcheck OMSconsole $OMSHOST $PORT_OMS tls1
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA tls1
sslcheck OMSupload $OMSHOST $PORT_UPL tls1
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER tls1

echo -e "\n\t(1c) $OPENSSL_PERMIT_FORBID_NON_TLS1_2 TLSv1.1 connections"
sslcheck Agent $OMSHOST $PORT_AGENT tls1_1
sslcheck BIPublisher $OMSHOST $PORT_BIP tls1_1
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER tls1_1
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS tls1_1
sslcheck OMSconsole $OMSHOST $PORT_OMS tls1_1
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA tls1_1
sslcheck OMSupload $OMSHOST $PORT_UPL tls1_1
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER tls1_1

echo -e "\n\t(1c) Permit TLSv1.2 connections"
sslcheck Agent $OMSHOST $PORT_AGENT tls1_2
sslcheck BIPublisher $OMSHOST $PORT_BIP tls1_2
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER tls1_2
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS tls1_2
sslcheck OMSconsole $OMSHOST $PORT_OMS tls1_2
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA tls1_2
sslcheck OMSupload $OMSHOST $PORT_UPL tls1_2
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER tls1_2

echo -e "\n(2) Checking supported ciphers at SSL/TLS endpoints (see notes 2138391.1, 1067411.1)"
ciphercheck Agent $OMSHOST $PORT_AGENT
ciphercheck BIPublisher $OMSHOST $PORT_BIP
ciphercheck NodeManager $OMSHOST $PORT_NODEMANAGER
ciphercheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS
ciphercheck OMSconsole $OMSHOST $PORT_OMS
ciphercheck OMSproxy $OMSHOST $PORT_OMS_JAVA
ciphercheck OMSupload $OMSHOST $PORT_UPL
ciphercheck WLSadmin $OMSHOST $PORT_ADMINSERVER

echo -e "\n(3) Checking self-signed and demonstration certificates at SSL/TLS endpoints (see notes 1367988.1, 1399293.1, 1593183.1, 1527874.1, 123033.1, 1937457.1)"
certcheck Agent $OMSHOST $PORT_AGENT
democertcheck Agent $OMSHOST $PORT_AGENT
certcheck BIPublisher $OMSHOST $PORT_BIP
democertcheck BIPublisher $OMSHOST $PORT_BIP
certcheck NodeManager $OMSHOST $PORT_NODEMANAGER
democertcheck NodeManager $OMSHOST $PORT_NODEMANAGER
certcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS
democertcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS
certcheck OMSconsole $OMSHOST $PORT_OMS
democertcheck OMSconsole $OMSHOST $PORT_OMS
certcheck OMSproxy $OMSHOST $PORT_OMS_JAVA
democertcheck OMSproxy $OMSHOST $PORT_OMS_JAVA
certcheck OMSupload $OMSHOST $PORT_UPL
democertcheck OMSupload $OMSHOST $PORT_UPL
certcheck WLSadmin $OMSHOST $PORT_ADMINSERVER
democertcheck WLSadmin $OMSHOST $PORT_ADMINSERVER


echo -e "\n(4) Checking EM13c Oracle home patch levels against $PATCHDATE baseline (see notes $PATCHNOTE, 822485.1, 1470197.1)"

if [[ $RUN_DB_CHECK -eq 1 ]]; then

	if [[ "$REPOS_DB_VERSION" == "12.1.0.2.0" ]]; then
		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) DATABASE BUNDLE PATCH: 12.1.0.2.170117 (JAN2017) (24732088)... "
		opatchcheck ReposDBHome $REPOS_DB_HOME 24732088

		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) Database PSU 12.1.0.2.170117, Oracle JavaVM Component (JAN2017) (24917972)... "
		opatchcheck ReposDBHome $REPOS_DB_HOME 24917972

		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) OCW Interim patch for 25101514 (25101514)... "
		opatchcheck ReposDBHome $REPOS_DB_HOME 25101514

		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) EM QUERY WITH SQL_ID 4RQ83FNXTF39U PERFORMS POORLY ON ORACLE 12C RELATIVE TO 11G (20243268)... "
		opatchcheck ReposDBHome $REPOS_DB_HOME 20243268
	fi

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.ENCRYPTION_TYPES_SERVER parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.ENCRYPTION_TYPES_SERVER $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.ENCRYPTION_SERVER parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.ENCRYPTION_SERVER $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.ENCRYPTION_TYPES_CLIENT parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.ENCRYPTION_TYPES_CLIENT $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.ENCRYPTION_CLIENT parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.ENCRYPTION_CLIENT $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.CRYPTO_CHECKSUM_SERVER parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.CRYPTO_CHECKSUM_SERVER $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SQLNET.CRYPTO_CHECKSUM_CLIENT parameter (76629.1, 2167682.1)... "
	paramcheck SQLNET.CRYPTO_CHECKSUM_CLIENT $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SSL_VERSION parameter (1545816.1)... "
	paramcheck SSL_VERSION $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) sqlnet.ora SSL_CIPHER_SUITES parameter (1545816.1)... "
	paramcheck SSL_CIPHER_SUITES $REPOS_DB_HOME sqlnet.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) listener.ora SSL_VERSION parameter (1545816.1)... "
	paramcheck SSL_VERSION $REPOS_DB_HOME listener.ora

	echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) listener.ora SSL_CIPHER_SUITES parameter (1545816.1)... "
	paramcheck SSL_CIPHER_SUITES $REPOS_DB_HOME listener.ora
fi

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM-AGENT BUNDLE PATCH 13.2.0.0.170228 (25414194)... "
opatchcheck Agent $AGENT_HOME 25414194

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM DB PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING (25501452)... "
opatchplugincheck Agent $AGENT_HOME 25501452 oracle.sysman.db.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM DB PLUGIN BUNDLE PATCH 13.2.1.0.161231 DISCOVERY (25197692)... "
opatchplugincheck Agent $AGENT_HOME 25197692 oracle.sysman.db.discovery.plugin_13.2.1.0.0

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM FMW PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING (25501427)... "
opatchplugincheck Agent $AGENT_HOME 25501427 oracle.sysman.emas.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM FMW PLUGIN BUNDLE PATCH 13.2.1.0.170228 DISCOVERY (25501430)... "
opatchplugincheck Agent $AGENT_HOME 25501430 oracle.sysman.emas.discovery.plugin_13.2.1.0.0

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM SI PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING (25501408)... "
opatchplugincheck Agent $AGENT_HOME 25501408 oracle.sysman.si.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM-BEACON BUNDLE PATCH 13.2.0.0.161231 (25162444)... "
opatchplugincheck Agent $AGENT_HOME 25162444 oracle.sysman.beacon.agent.plugin_13.2.0.0.0

echo -ne "\n\t(4c) OMS CHAINED AGENT HOME ($AGENT_HOME) EM EXADATA PLUGIN BUNDLE PATCH 13.2.1.0.170228 DISCOVERY (25501436)... "
opatchplugincheck Agent $AGENT_HOME 25501436 oracle.sysman.xa.discovery.plugin_13.2.1.0.0

echo -ne "\n\t(4c) *NEW* OMS CHAINED AGENT HOME ($AGENT_HOME) EM EXADATA PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING (25362875)... "
opatchplugincheck Agent $AGENT_HOME 25362875 oracle.sysman.xa.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) *NEW* OMS CHAINED AGENT HOME ($AGENT_HOME) EM FUSION APPS PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING (25522944)... "
opatchplugincheck Agent $AGENT_HOME 25522944 oracle.sysman.emfa.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) *NEW* OMS CHAINED AGENT HOME ($AGENT_HOME) EM OVI PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING (25501416)... "
opatchplugincheck Agent $AGENT_HOME 25501416 oracle.sysman.vi.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) *NEW* OMS CHAINED AGENT HOME ($AGENT_HOME) EM OVI PLUGIN BUNDLE PATCH 13.2.1.0.170131 DISCOVERY (25362898)... "
opatchplugincheck Agent $AGENT_HOME 25362898 oracle.sysman.vi.discovery.plugin_13.2.1.0.0

echo -ne "\n\t(4c) *NEW* OMS CHAINED AGENT HOME ($AGENT_HOME) EM VIRTUALIZATION PLUGIN BUNDLE PATCH 13.2.1.0.170131 MONITORING (25362890)... "
opatchplugincheck Agent $AGENT_HOME 25362890 oracle.sysman.vt.agent.plugin_13.2.1.0.0

echo -ne "\n\t(4c) *NEW* OMS CHAINED AGENT HOME ($AGENT_HOME) EM VIRTUALIZATION PLUGIN BUNDLE PATCH 13.2.1.0.161231 DISCOVERY (25197712)... "
opatchplugincheck Agent $AGENT_HOME 25197712 oracle.sysman.vt.discovery.plugin_13.2.1.0.0

echo -ne "\n\t(4d) OMS HOME ($OMS_HOME) TRACKING BUG TO REGISTER META VERSION FROM PS4 AND 13.1 BUNDLE PATCHES IN 13.2 (SYSTEM PATCH) (23603592)... "
omspatchercheck OMS $OMS_HOME 23603592

echo -ne "\n\t(4d) OMS HOME ($OMS_HOME) TRACKING BUG FOR BACK-PORTING 24588124 OMS SIDE FIX (25163555)... "
omspatchercheck OMS $OMS_HOME 25163555

echo -ne "\n\t(4d) OMS HOME ($OMS_HOME) MERGE REQUEST ON TOP OF 12.1.3.0.0 FOR BUGS 24571979 24335626 (25322055)... "
omspatchercheck OMS $OMS_HOME 25322055

echo -ne "\n\t(4d) OMS HOME ($OMS_HOME) MERGE REQUEST ON TOP OF 12.1.3.0.0 FOR BUGS 22557350 19901079 20222451 (24329181)... "
omspatchercheck OMS $OMS_HOME 24329181

echo -ne "\n\t(4d) *NEW* OMS HOME ($OMS_HOME) MERGE REQUEST ON TOP OF 13.2.0.0.0 FOR BUGS 25497622 25497731 25506784 (25604219)... "
omspatchercheck OMS $OMS_HOME 25604219

echo -ne "\n\t(4d) OMS HOME ($OMS_HOME) OPSS-OPC Bundle Patch 12.1.3.0.170117 (25221285)... "
omspatchercheck OMS $OMS_HOME 25221285

echo -ne "\n\t(4d) OMS HOME ($OMS_HOME) ENTERPRISE MANAGER FOR OMS PLUGINS 13.2.0.0.170228 (25501489)... "
omspatchercheck OMS $OMS_HOME 25501489

echo -ne "\n\t(4d) OMS HOME ($MW_HOME) WLS PATCH SET UPDATE 12.1.3.0.170117 (24904852)... "
opatchcheck WLS $MW_HOME 24904852

echo -ne "\n\t(4d) *NEW* OMS HOME ($MW_HOME) TOPLINK SECURITY PATCH UPDATE CPUJUL2016 (24327938)... "
opatchcheck WLS $MW_HOME 24327938

echo -e "\n(5) Checking EM13cR2 Java patch levels against $PATCHDATE baseline (see notes 2241373.1, 2241358.1)"

echo -ne "\n\t(5a) *UPDATED* Common Java ($MW_HOME/oracle_common/jdk) JAVA SE JDK VERSION 1.7.0-131 (13079846)... "
javacheck JAVA $MW_HOME/oracle_common/jdk

echo -ne "\n\t(5b) *NEW* OMS Chained Agent Java ($AGENT_HOME/oracle_common/jdk) JAVA SE JDK VERSION 1.7.0-131 (13079846)... "
javacheck JAVA $AGENT_HOME/oracle_common/jdk

echo -e "\n(6) Checking EM13cR2 OPatch/OMSPatcher patch levels against $PATCHDATE requirements (see patch 25197714 README, patches 6880880 and 19999993)"

echo -ne "\n\t(6a) OPatch ($MW_HOME/OPatch) VERSION 13.9.1.0.0 or newer... "
patchercheck OPatch $MW_HOME/OPatch 13.9.1.0.0

echo -ne "\n\t(6b) OMSPatcher ($MW_HOME/OPatch) VERSION 13.8.0.0.1 or newer... "
patchercheck OMSPatcher $MW_HOME/OMSPatcher 13.8.0.0.1


if [[ "$EMCLI_CHECK" -eq 1 ]]; then
    echo -e "\n(7) *NEW* Confirmed EMCLI logged-in state. Proceeding with EMCLI-based checks."
    emclicheck oracle_emd oracle.sysman.db agent 13.2.1.0.0 25501452 7a "EM DB PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING"
    emclicheck oracle_emd oracle.sysman.db discovery 13.2.1.0.0 25197692 7a "EM DB PLUGIN BUNDLE PATCH 13.2.1.0.161231 DISCOVERY"
    emclicheck oracle_emd oracle.sysman.emas agent 13.2.1.0.0 25501427 7a "EM FMW PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING"
    emclicheck oracle_emd oracle.sysman.emas discovery 13.2.1.0.0 25501430 7a "EM FMW PLUGIN BUNDLE PATCH 13.2.1.0.170228 DISCOVERY"
    emclicheck oracle_emd oracle.sysman.si agent 13.2.1.0.0 25501408 7a "EM SI PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING"
    emclicheck oracle_emd oracle.sysman.beacon agent 13.2.0.0.0 25162444 7a "EM-BEACON BUNDLE PATCH 13.2.0.0.161231"
    emclicheck oracle_emd oracle.sysman.xa discovery 13.2.1.0.0 25501436 7a "EM EXADATA PLUGIN BUNDLE PATCH 13.2.1.0.170228 DISCOVERY"
    emclicheck oracle_emd oracle.sysman.xa agent 13.2.1.0.0 25362875 7a "EM EXADATA PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING"
    emclicheck oracle_emd oracle.sysman.emfa agent 13.2.1.0.0 25522944 7a "EM FUSION APPS PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING"
    emclicheck oracle_emd oracle.sysman.vi agent 13.2.1.0.0 25501416 7a "EM OVI PLUGIN BUNDLE PATCH 13.2.1.0.170228 MONITORING"
    emclicheck oracle_emd oracle.sysman.vi discovery 13.2.1.0.0 25362898 7a "EM OVI PLUGIN BUNDLE PATCH 13.2.1.0.170131 DISCOVERY"
    emclicheck oracle_emd oracle.sysman.vt agent 13.2.1.0.0 25362890 7a "EM VIRTUALIZATION PLUGIN BUNDLE PATCH 13.2.1.0.170131 MONITORING"
    emclicheck oracle_emd oracle.sysman.vt discovery 13.2.1.0.0 25197712 7a "EM VIRTUALIZATION PLUGIN BUNDLE PATCH 13.2.1.0.161231 DISCOVERY"
else
    echo -e "\n(7) Not logged in to EMCLI. Skipping EMCLI-based checks. To enable EMCLI checks, login to EMCLI with an OEM user that has configured default normal database credentials and default host credentials for your repository database target, then run this script again."
fi

echo
echo

if [[ $FAIL_COUNT -gt "0" ]]; then
	echo "Failed test count: $FAIL_COUNT - Review output"
	test $VERBOSE_CHECKSEC -ge 1 && echo -e $FAIL_TESTS
else
	echo "All tests succeeded."
fi

echo
echo "Visit https://pardydba.wordpress.com/2016/10/28/securing-oracle-enterprise-manager-13cr2/ for more information."
echo "Download the latest version from https://raw.githubusercontent.com/brianpardy/em13c/master/checksec13R2.sh"
echo

exit
