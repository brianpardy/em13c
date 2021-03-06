#!/bin/bash
#
# This script should examine your EM13c environment, identify the ports
# each component uses, and check for usage of encryption protocols older
# then TLSv1.2, as well as make sure that weak and medium strength
# cipher suites get rejected. It will also validate your system comparing
# against the latest recommended patches and also flags the use of demo
# or self-signed certificates.
#
# LICENSE: PUBLIC DOMAIN, USE AT YOUR OWN RISK
#
#	Released	v0.1:	Initial beta release 5 Apr 2016
#	Changes		v0.2:	Updated for current patches
#	Changes		v0.3:	APR2016 patchset added
#	Changes		v0.4:	Plugin updates for 20160429
#	Changes		v0.5:	Plugin updates for 20160531
#	Changes		v0.6:	Plugin/OMS/DB updates for 20160719 CPU + Java check
#	Changes		v0.7:	Plugin/OMS updates for 20160816 bundles
#						Support for SLES11 OpenSSL 1 parallel package
#						Add checks for TLSv1.1, TLSv1.2
#						Permit only TLSv1.2 where supported by OpenSSL
#	Changes		v0.8:	Fix broken check for SSL_CIPHER_SUITES
#						Add checks for ENCRYPTION_SERVER, ENCRYPTION_CLIENT,
#						CRYPTO_CHECKSUM_SERVER, CRYPTO_CHECKSUM_CLIENT,
#						ENCRYPTION_TYPES_SERVER, ENCRYPTION_TYPES_CLIENT,
#						CRYPTO_CHECKSUM_TYPES_SERVER, CRYPTO_CHECKSUM_TYPES_CLIENT
#	Changes		v0.9:	Plugin updates for 20160920
#						Support TLSv1.2 when available in certcheck,
#						democertcheck, and ciphercheck
#	Changes		v1.0:	Converted to EM13cR2, converted repository DB checks
#						to use DBBP Bundle Patch (aka Exadata patch), not PSU
#	Changes		v1.1:	Updated for 20161231 EM13cR2 patches.
#						Updated for 20170117 security patches.
#						Add check for OPatch and OMSPatcher versions.
#	Changes		v1.2:	Updated for 20170131 bundle patches.
#	Changes		v1.3:	Updated for 20170228 bundle patches.
#	Changes		v1.4:	Added patches 25604219 and 24327938
#						Updated Java check to 1.7.0_131
#	Changes		v1.5:	Add check for chained agent Java version
#	Changes		v1.6:	Updated note references.
#						Added plugin patch checks for OMS chained agent
#						for non-default discovery/monitoring plugins
#						not previously checked. If you do not have
#						those plugins installed, the script will not
#						indicate failure due to the missing patch.
#						Added EMCLI check. If you login to EMCLI
#						before running ./checksec13R2.sh, the script
#						will soon check additional items using EMCLI.
#	Changes		v2.0:	Now checking plugin bundle patches on all agents
#						using EMCLI. Run the script while not logged in
#						to EMCLI for instructions. Login to EMCLI and run
#						the script to use the new functionality.
#						If not logged in, still runs all non-EMCLI checks.
#	Changes		v2.1:	Now checking OPatch versions on all agents using
#						EMCLI. Now checking self-signed/demo certs on all
#						agents using EMCLI. Now caching key EMCLI output
#						to decrease runtime.
#	Changes		v2.2:	Gather OPatch/OMSPatcher output at the beginning
#						of the script and cache it during the run to improve
#						runtime. Turned off verbose-by-default, added "-v"
#						commandline switch to enable verbose run.
#						Now checks agent bundle patch presence on all agents.
#						Cache execute_sql agent patch output to improve runtime.
#						Cache agent home list to improve runtime.
#						Huge runtime improvements vs previous release.
#						Remove duplicated code for cert checks
#	Changes		v2.3:	Get agent home directories from a different repo table
#						Update OPatch/OMSPatcher versions
#	Changes		v2.4:	Include 20170418 PSU
#	Changes		v2.5:	Include 20170418 DBBP and 20170418 WLS and Java 1.7.0_141
#						Update MOS note references, add agent bundle 20170331
#	Changes		v2.6:	Add agent bundle 20170331, ADF 21849941, OPSS 22748215
#						Update plugin bundle patches for 13.2.1 plugin line
#	Changes		v2.7:	Add check for APEX version on repository DB
#						Handle cases where OpenSSL has no LOW strength ciphers
#						Fix opatchplugincheck for directories leftover from
#						install of previous plugin versions.
#						Fixed some missing bundle patches in EMCLI agent checks.
#						Update agent+plugin bundle patches to 20170430
#	Changes		v2.8:	Update for 20170531 patch release
#	Changes		v2.9:	Update for first set of 13.2.2 plugin bundle patches
#	Changes		v2.10:	Update for 20170630 plugin bundle patches
#	Changes		v2.11:	Update for 20170718 OMS, DB, WLS PSU releases
#	Changes		v2.12:	Update for 20170731 plugin bundle patches
#	Changes		v2.13:	Update for 20170814 off cycle DB PSU
#	Changes		v2.14:	Update for 20170831 plugin bundle patches
#	Changes		v2.15:	Update for 20170930 plugin bundle patches + 13.2.3
#	Changes		v2.16:	Add Cloud Services Management plugin, OMS PSU 171017
#	Changes		v2.17:	Update for DB PROACTIVE PSU 171017 & OCW PSU (JVM PSU TBD?)
#	Changes		v2.18:	Update JVM PSU 171017
#	Changes		v2.19:	Add OSS CPUOCT2017, update WLS PSU 171017
#	Changes		v2.20:	Update SSL_VERSION check to 1.2, Java JDK to 1.7.0_161
#	Changes		v2.21:	Update for 20171031 bundle patches released 20171110, ZDLRA patch
#						Bug fixes reported by JS - EMCLI definition, AIX hostname -f
#							-oh $MW_HOME in patchercheck
#						Enhancements from JS: improve minimum version calc for OPatch
#							merge certcheck/democertcheck
#							use emcli list, not emcli execute_sql
#						Now needs execute ad hoc sql using EMCLI list verb
#							ACCESS_EMCLI_SQL_LIST_VERB
#	Changes		v2.22:	Abort if running as user root. Move cache files to $TMPDIR.
#	Changes		v2.23:	Update OPatch 13.9.2.1.0 warning, add patch 27155076
#	Changes		v2.24:	Update for 20171130 bundle patches
#	Changes		v2.25:	Update for 20171231 bundle patches
#	Changes		v2.26:	Update for January 2018 security patches
#	Changes		v2.27:	Update for 20180131 bundle patches and Java 1.7.0_171
#						Improve OPatch version check on agents to tolerate minimum version
#						Rewrite SQL for agent patch list to avoid EMCLI too many rows err
#						Update for 20180116 OMS PSU
#	Changes		v2.28:	Update for 20180228 bundle patches
#	Changes		v2.29:	Update for 20180331 bundle patches
#	Changes		v2.30:	Update for 20180417 security patches, OPatch 13.9.3.2.0
#	Changes		v2.31:	Update for 20180430 bundle patches
#	Changes		v2.32:	Update for 20180531 bundle patches
#	Changes		v2.33:	Update for 20180630 bundle patches
#	Changes		v2.34:	Update for 20180731 bundle patches, 20180717 OMS PSU, etc
#	Changes		v2.35:	Update for 20180831 bundle patches, move defs to variables
#						Check for use of EMCLI account without default creds
#						Fixed virtualization plugin 13.2.3 no-emcli check that was broken
#	Changes		v2.36:	Update for 20180930 bundle patches
#	Changes		v2.37:	Update for 20181016 OMS PSU
#	Changes		v2.38:	Update for 20181016 Critical Patch Update: APEX, DB, WLS
#	Changes		v2.39:	Bugfixes for issue #7, long agent names truncated
#						Fix bug introduced in 2.35 displaying plugin bundle patch names
#						Update Java to 1.7.0_201
#	Changes		v2.40:	Revert Java 1.7.0_201 check. Causes down targets in OEM.
#	Changes		v2.41:	Updates as of 20190731 patches
#
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
# Thanks to Rafał Ramocki, who noted an issue with OpenSSL on Oracle Linux
# 6.9 where OpenSSL does not have LOW strength ciphers available, causing
# an error in the script.
#
# Thanks to Jan Schnackenberg who reported many general and AIX-specific issues
# and provided patches to resolve them, including a merged replacement for
# the self-signed and demo certificate checks, a greatly improved multi-dot
# version string comparison, better handling for endpoints not supporting
# TLSv1.2, and bugfixes for the patchercheck and variable definitions.
#
# Thanks to lamahmud on github who reported an issue causing truncation of long
# agent names in emcli output, and useless output from emcli when an agent is
# down, and provided a fix.
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
# -	Login to EMCLI using an OEM user account
# -	Make sure the OEM user account can execute EMCLI execute_sql,
#	execute_hostcmd, and list
# -	Make sure the OEM user account has specified default normal database
#	credentials and default host credentials for the repository database
#	target.
#	* This will enable plugin bundle patch checks on all agents.
# -	Make sure the OEM user account has specified preferred credentials for
#	all host targets where agents run
#	* This will enable Java version checks on all agents.
#
# The create_user_for_checksec13R2.sh script provided in the same repo
# as this script will create a user with the necessary permissions and
# prompt for the necessary named credentials. Download it from:
# https://raw.githubusercontent.com/brianpardy/em13c/master/create_user_for_checksec13R2.sh
#
#
# Dedicated to our two Lhasa Apsos:
#	Lucy (6/13/1998 - 3/13/2015)
#	Ethel (6/13/1998 - 7/31/2015)
#
# And our new beagle/poodle/boxer/dalmation/pekingese/cockerspaniel/pug mutt
#	Helix b. 1/2/2017
#

### Begin user configurable section

JAVA_CHECK_VERSION="1.7.0_171"
OPATCH_CHECK_VERSION="13.9.3.3.0"
OPATCH_AGENT_CHECK_VERSION="13.9.3.3.0"
OMSPATCHER_CHECK_VERSION="13.8.0.0.3"

### Group the main set of frequently revised patches here
#OMSSIDE1321=27523593
#OMSSIDE1321DATE=20180228

#OMSSIDE1322=28628403
#OMSSIDE1322DATE=20180930

#OMSSIDE1323=28628415
#OMSSIDE1323DATE=20180930

OMSSIDE1321=27523593
OMSSIDE1321DATE=20180228

OMSSIDE1322=30029041
OMSSIDE1322DATE=20190731

OMSSIDE1323=30029043
OMSSIDE1323DATE=20190731

OMSSIDE1324=29201674
OMSSIDE1324DATE=20190131

#OMSPSUPATCH=28717501
#OMSPSUDATE=181016
#OMSPSUDESC="ENTERPRISE MANAGER BASE PLATFORM - OMS 13.2.0.0.$OMSPSUDATE PSU ($OMSPSUPATCH)"

#OMSPSUPATCH=28970534
#OMSPSUDATE=190115
#OMSPSUDESC="EMBP Patch Set Update 13.2.0.0.$OMSPSUDATE PSU ($OMSPSUPATCH)"

OMSPSUPATCH=29835501
OMSPSUDATE=190716
OMSPSUDESC="EMBP Patch Set Update 13.2.0.0.$OMSPSUDATE PSU ($OMSPSUPATCH)"

OHSSPUPATCH=27244723
OHSSPUDATE=2018JUL
OHSSPUDESC="ORACLE HTTP SERVER - OHS 12.1.3 SPU $OHSSPUDATE ($OHSSPUPATCH)"

#DB12102PSUPATCH=28259867
#DB12102PSUDATE=181016
#DB12102PSUDESC="DATABASE BUNDLE PATCH 12.1.0.2.$DB12102PSUDATE ($DB12102PSUPATCH)"

DB12102PSUPATCH=29496791
DB12102PSUDATE=190716
DB12102PSUDESC="DATABASE BUNDLE PATCH 12.1.0.2.$DB12102PSUDATE ($DB12102PSUPATCH)"

#DB12102JAVAPATCH=28440711
#DB12102JAVADATE=181016
#DB12102JAVADESC="ORACLE JAVAVM COMPONENT 12.1.0.2.$DB12102JAVADATE ($DB12102JAVAPATCH)"

DB12102JAVAPATCH=29774383
DB12102JAVADATE=190716
DB12102JAVADESC="ORACLE JAVAVM COMPONENT 12.1.0.2.$DB12102JAVADATE ($DB12102JAVAPATCH)"

#AGTBUNDLEPATCH=28533438
#AGTBUNDLEDATE=180930
#AGTBUNDLEDESC="EM-AGENT BUNDLE PATCH 13.2.0.0.$AGTBUNDLEDATE"

#AGTBUNDLEPATCH=29121337
#AGTBUNDLEDATE=190131
#AGTBUNDLEDESC="EM-AGENT BUNDLE PATCH 13.2.0.0.$AGTBUNDLEDATE"

AGTBUNDLEPATCH=29920791
AGTBUNDLEDATE=190731
AGTBUNDLEDESC="EM-AGENT BUNDLE PATCH 13.2.0.0.$AGTBUNDLEDATE"

#WLSPSUPATCH=28298916
#WLSPSUDATE=181016
#WLSPSUDESC="WLS PATCH SET UPDATE 12.1.3.0.$WLSPSUDATE ($WLSPSUPATCH)"

WLSPSUPATCH=29633448
WLSPSUDATE=190716
WLSPSUDESC="WLS PATCH SET UPDATE 12.1.3.0.$WLSPSUDATE ($WLSPSUPATCH)"

### Database Plugin
DBPLGDESC="EM DB PLUGIN BUNDLE PATCH"

DBPLG1322MONPATCH=29904161
DBPLG1322MONDATE=190630
DBPLG1322MONDESC="$DBPLGDESC 13.2.2.0.$DBPLG1322MONDATE MONITORING"
DBPLG1322DISCPATCH=28479031
DBPLG1322DISCDATE=180831
DBPLG1322DISCDESC="$DBPLGDESC 13.2.2.0.$DBPLG1322DISCDATE DISCOVERY"

DBPLG1321MONPATCH=27523557
DBPLG1321MONDATE=180228
DBPLG1321MONDESC="$DBPLGDESC 13.2.1.0.$DBPLG1321MONDATE MONITORING"
DBPLG1321DISCPATCH=27372651
DBPLG1321DISCDATE=180131
DBPLG1321DISCDESC="$DBPLGDESC 13.2.1.0.$DBPLG1321DISCDATE DISCOVERY"


### Beacon Plugin
BEACONPLGDESC="EM BEACON BUNDLE PATCH"

BEACONPLG1320PATCH=25162444
BEACONPLG1320DATE=161231
BEACONPLG1320DESC="$BEACONPLGDESC 13.2.0.0.$BEACONPLG1320DATE"


### Exadata Plugin
EXAPLGDESC="EM EXADATA PLUGIN BUNDLE PATCH"

EXAPLG1322MONPATCH=29389645
EXAPLG1322MONDATE=190228
EXAPLG1322MONDESC="$EXAPLGDESC 13.2.2.0.$EXAPLG1322MONDATE MONITORING"
EXAPLG1322DISCPATCH=27664136
EXAPLG1322DISCDATE=180331
EXAPLG1322DISCDESC="$EXAPLGDESC 13.2.2.0.$EXAPLG1322DISCDATE DISCOVERY"

EXAPLG1321MONPATCH=25362875
EXAPLG1321MONDATE=170131
EXAPLG1321MONDESC="$EXAPLGDESC 13.2.1.0.$EXAPLG1321MONDATE MONITORING"
EXAPLG1321DISCPATCH=25501436
EXAPLG1321DISCDATE=170228
EXAPLG1321DISCDESC="$EXAPLGDESC 13.2.1.0.$EXAPLG1321DISCDATE DISCOVERY"


### Fusion Application Plugin
FMWAPPSPLGDESC="EM FUSION APPS PLUGIN BUNDLE PATCH"

FMWAPPSPLG1321MONPATCH=25522944
FMWAPPSPLG1321MONDATE=170228
FMWAPPSPLG1321MONDESC="$FMWAPPSPLGDESC 13.2.1.0.$FMWAPPSPLG1321MONDATE MONITORING"
FMWAPPSPLG1321DISCPATCH=25985223
FMWAPPSPLG1321DISCDATE=170531
FMWAPPSPLG1321DISCDESC="$FMWAPPSPLGDESC 13.2.1.0.$FMWAPPSPLG1321DISCDATE DISCOVERY"

FMWAPPSPLG1322MONPATCH=26817739
FMWAPPSPLG1322MONDATE=170930
FMWAPPSPLG1322MONDESC="$FMWAPPSPLGDESC 13.2.2.0.$FMWAPPSPLG1322MONDATE MONITORING"
FMWAPPSPLG1322DISCPATCH=26238802
FMWAPPSPLG1322DISCDATE=170630
FMWAPPSPLG1322DISCDESC="$FMWAPPSPLGDESC 13.2.2.0.$FMWAPPSPLG1322DISCDATE DISCOVERY"

FMWAPPSPLG1323MONPATCH=27110221
FMWAPPSPLG1323MONDATE=190131
FMWAPPSPLG1323MONDESC="$FMWAPPSPLGDESC 13.2.3.0.$FMWAPPSPLG1323MONDATE MONITORING"
#FMWAPPSPLG1323DISCPATCH=NA
#FMWAPPSPLG1323DISCDATE=NA
#FMWAPPSPLG1323DISCDESC="$FMWAPPSPLGDESC 13.2.3.0.$FMWAPPSPLG1323DISCDATE DISCOVERY"


### Fusion Middleware Plugin
FMWPLGDESC="EM FMW PLUGIN BUNDLE PATCH"

FMWPLG1321MONPATCH=26568791
FMWPLG1321MONDATE=170831
FMWPLG1321MONDESC="$FMWPLGDESC 13.2.1.0.$FMWPLG1321MONDATE MONITORING"
FMWPLG1321DISCPATCH=25501430
FMWPLG1321DISCDATE=170228
FMWPLG1321DISCDESC="$FMWPLGDESC 13.2.1.0.$FMWPLG1321DISCDATE DISCOVERY"

FMWPLG1322MONPATCH=28947165
FMWPLG1322MONDATE=181130
FMWPLG1322MONDESC="$FMWPLGDESC 13.2.2.0.$FMWPLG1322MONDATE MONITORING"
FMWPLG1322DISCPATCH=27243226
FMWPLG1322DISCDATE=171231
FMWPLG1322DISCDESC="$FMWPLGDESC 13.2.2.0.$FMWPLG1322DISCDATE DISCOVERY"

FMWPLG1323MONPATCH=30065020
FMWPLG1323MONDATE=190731
FMWPLG1323MONDESC="$FMWPLGDESC 13.2.3.0.$FMWPLG1323MONDATE MONITORING"
FMWPLG1323DISCPATCH=28347335
FMWPLG1323DISCDATE=180731
FMWPLG1323DISCDESC="$FMWPLGDESC 13.2.3.0.$FMWPLG1323DISCDATE DISCOVERY"


### Oracle Virtualization Infrastructure Plugin
OVIPLGDESC="EM OVI PLUGIN BUNDLE PATCH"

OVIPLG1321MONPATCH=25501416
OVIPLG1321MONDATE=170228
OVIPLG1321MONDESC="$OVIPLGDESC 13.2.1.0.$OVIPLG1321MONDATE MONITORING"
OVIPLG1321DISCPATCH=25362898
OVIPLG1321DISCDATE=170131
OVIPLG1321DISCDESC="$OVIPLGDESC 13.2.1.0.$OVIPLG1321DISCDATE DISCOVERY"

OVIPLG1322MONPATCH=27830292
OVIPLG1322MONDATE=180430
OVIPLG1322MONDESC="$OVIPLGDESC 13.2.2.0.$OVIPLG1322MONDATE MONITORING"
OVIPLG1322DISCPATCH=26404920
OVIPLG1322DISCDATE=170731
OVIPLG1322DISCDESC="$OVIPLGDESC 13.2.2.0.$OVIPLG1322DISCDATE DISCOVERY"

OVIPLG1323MONPATCH=29762495
OVIPLG1323MONDATE=190531
OVIPLG1323MONDESC="$OVIPLGDESC 13.2.3.0.$OVIPLG1323MONDATE MONITORING"
OVIPLG1323DISCPATCH=29211702
OVIPLG1323DISCDATE=190131
OVIPLG1323DISCDESC="$OVIPLGDESC 13.2.3.0.$OVIPLG1323DISCDATE DISCOVERY"


### Oracle System Infrastructure Plugin
SIPLGDESC="EM SI PLUGIN BUNDLE PATCH"

SIPLG1321MONPATCH=25985080
SIPLG1321MONDATE=170531
SIPLG1321MONDESC="$SIPLGDESC 13.2.1.0.$SIPLG1321MONDATE MONITORING"
#SIPLG1321DISCPATCH=NA
#SIPLG1321DISCDATE=NA
#SIPLG1321DISCDESC="$SIPLGDESC 13.2.1.0.$SIPLG1321DISCDATE DISCOVERY"

SIPLG1322MONPATCH=27830324
SIPLG1322MONDATE=180430
SIPLG1322MONDESC="$SIPLGDESC 13.2.2.0.$SIPLG1322MONDATE MONITORING"
#SIPLG1322DISCPATCH=NA
#SIPLG1322DISCDATE=NA
#SIPLG1322DISCDESC="$SIPLGDESC 13.2.2.0.$SIPLG1322DISCDATE DISCOVERY"

SIPLG1323MONPATCH=30065031
SIPLG1323MONDATE=190731
SIPLG1323MONDESC="$SIPLGDESC 13.2.3.0.$SIPLG1323MONDATE MONITORING"
#SIPLG1323DISCPATCH=NA
#SIPLG1323DISCDATE=NA
#SIPLG1323DISCDESC="$SIPLGDESC 13.2.3.0.$SIPLG1323DISCDATE DISCOVERY"


### Zero Data Loss Recovery Application Plugin
ZDLRAPLGDESC="EM ZERO DATA LOSS RECOVERY APPLIANCE PLUGIN BUNDLE PATCH"

ZDLRAPLG1322MONPATCH=29658865
ZDLRAPLG1322MONDATE=190430
ZDLRAPLG1322MONDESC="$ZDLRAPLGDESC 13.2.2.0.$ZDLRAPLG1321MONDATE MONITORING"
#ZDLRAPLG1322DISCPATCH=NA
#ZDLRAPLG1322DISCDATE=NA
#ZDLRAPLG1322DISCDESC="$ZDLRAPLGDESC 13.2.1.0.$ZDLRAPLG1321DISCDATE DISCOVERY"

### Oracle CSM Plugin
CSMPLGDESC="EM CSM PLUGIN BUNDLE PATCH"

CSMPLG1322MONPATCH=26817793
CSMPLG1322MONDATE=170930
CSMPLG1322MONDESC="$CSMPLGDESC 13.2.2.0.$CSMPLG1322MONDATE MONITORING"
#CSMPLG1322DISCPATCH=NA
#CSMPLG1322DISCDATE=NA
#CSMPLG1322DISCDESC="$CSMPLGDESC 13.2.2.0.$CSMPLG1322DISCDATE DISCOVERY"

CSMPLG1323MONPATCH=28195773
CSMPLG1323MONDATE=180630
CSMPLG1323MONDESC="$CSMPLGDESC 13.2.3.0.$CSMPLG1323MONDATE MONITORING"
#CSMPLG1323DISCPATCH=NA
#CSMPLG1323DISCDATE=NA
#CSMPLG1323DISCDESC="$CSMPLGDESC 13.2.3.0.$CSMPLG1323DISCDATE DISCOVERY"


### Oracle Virtualization Plugin
VIRTPLGDESC="EM VIRTUALIZATION PLUGIN BUNDLE PATCH"

VIRTPLG1321MONPATCH=26741678
VIRTPLG1321MONDATE=180331
VIRTPLG1321MONDESC="$VIRTPLGDESC 13.2.1.0.$VIRTPLG1321MONDATE MONITORING"
VIRTPLG1321DISCPATCH=25197712
VIRTPLG1321DISCDATE=161231
VIRTPLG1321DISCDESC="$VIRTPLGDESC 13.2.1.0.$VIRTPLG1321DISCDATE DISCOVERY"

VIRTPLG1322MONPATCH=29893650
VIRTPLG1322MONDATE=190630
VIRTPLG1322MONDESC="$VIRTPLGDESC 13.2.2.0.$VIRTPLG1322MONDATE MONITORING"
#VIRTPLG1322DISCPATCH=
#VIRTPLG1322DISCDATE=
#VIRTPLG1322DISCDESC="$VIRTPLGDESC 13.2.2.0.$VIRTPLG1322DISCDATE DISCOVERY"

VIRTPLG1323MONPATCH=29893662
VIRTPLG1323MONDATE=190630
VIRTPLG1323MONDESC="$VIRTPLGDESC 13.2.3.0.$VIRTPLG1323MONDATE MONITORING"
VIRTPLG1323DISCPATCH=29893678
VIRTPLG1323DISCDATE=190630
VIRTPLG1323DISCDESC="$VIRTPLGDESC 13.2.3.0.$VIRTPLG1323DISCDATE DISCOVERY"

### End user configurable section


SCRIPTNAME=`basename $0`
PATCHDATE="31 Jul 2019"
PATCHNOTE="1664074.1, 2219797.1"
VERSION="2.41"
FAIL_COUNT=0
FAIL_TESTS=""

RUN_DB_CHECK=0
VERBOSE_CHECKSEC=2
EMCLI_CHECK=0

HOST_OS=`uname -s`
HOST_ARCH=`uname -m`

if [[ "${HOST_OS}" == "AIX" ]]; then
	OMSHOST=`hostname`
	WHOAMI=`/usr/bin/whoami`
else
	OMSHOST=`hostname -f`
	if [[ -x "/usr/ucb/whoami" ]]; then
		WHOAMI=`/usr/ucb/whoami`	# Solaris
	else
		WHOAMI=`/usr/bin/whoami`
	fi
fi

if [[ -z "${TMPDIR}" ]]; then
	TMPDIR=/tmp
fi

if [[ "${WHOAMI}" == "root" ]]; then
	echo "Please execute this script as the Oracle software owner, not the root account."
	exit 1
fi

ORAGCHOMELIST="/etc/oragchomelist"
ORATAB="/etc/oratab"
OPENSSL=`which openssl`


echo -e "Performing EM13c R2 security checkup version $VERSION on $OMSHOST at `date`.\n"

echo "Gathering info... "

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
	OPENSSL_CERTCHECK_PROTOCOL="tls1_2"
else
	OPENSSL_CERTCHECK_PROTOCOL="tls1"
fi

OPENSSL_CHECK_NO_LOW_CIPHERS=`$OPENSSL ciphers LOW 2>&1 | $GREP -c "Error in cipher list"`

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

if [[ -z "${AGENT_HOME}" ]]; then
	echo "AGENT_HOME not found in oraInventory, exiting..." 1>&2
	exit 1
fi

AGENT_TARGETS_XML="$AGENT_HOME/../agent_inst/sysman/emd/targets.xml"
REPOS_DB_TARGET_NAME=`$GREP 'Member TYPE="oracle_database"' $AGENT_TARGETS_XML | uniq | sed 's/^.*NAME="//' | sed 's/".*$//'`

EM_INSTANCE_BASE=`$GREP GCDomain $MW_HOME/domain-registry.xml | sed -e 's/.*=//' | sed -e 's/\/user_projects.*$//' | sed -e 's/"//'`

EMGC_PROPS="$EM_INSTANCE_BASE/em/EMGC_OMS1/emgc.properties"
EMBIP_PROPS="$EM_INSTANCE_BASE/em/EMGC_OMS1/embip.properties"

PORT_UPL=`$GREP EM_UPLOAD_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_OMS=`$GREP EM_CONSOLE_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_OMS_JAVA=`$GREP MS_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_NODEMANAGER=`$GREP EM_NODEMGR_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_BIP=`$GREP BIP_HTTPS_PORT $EMBIP_PROPS | awk -F= '{print $2}'`
PORT_BIP_OHS=`$GREP BIP_HTTPS_OHS_PORT $EMBIP_PROPS | awk -F= '{print $2}'`
PORT_ADMINSERVER=`$GREP AS_HTTPS_PORT $EMGC_PROPS | awk -F= '{print $2}'`
PORT_AGENT=`$AGENT_HOME/bin/emctl status agent | $GREP 'Agent URL' | sed -e 's/\/emd\/main\///' | sed -e 's/^.*://' | uniq`

REPOS_DB_CONNDESC=`$GREP EM_REPOS_CONNECTDESCRIPTOR $EMGC_PROPS | sed -e 's/EM_REPOS_CONNECTDESCRIPTOR=//' | sed -e 's/\\\\//g'`
REPOS_DB_HOST=`echo $REPOS_DB_CONNDESC | sed -e 's/^.*HOST=//' | sed -e 's/).*$//'`
REPOS_DB_SID=`echo $REPOS_DB_CONNDESC | sed -e 's/^.*SID=//' | sed -e 's/).*$//'`

EMCLI="$MW_HOME/bin/emcli"

echo -e "\tEM13c config... OK"

if [[ "$REPOS_DB_HOST" == "$OMSHOST" ]]; then
	echo -ne "\tRepos DB... "
	REPOS_DB_HOME=`$GREP "$REPOS_DB_SID:" $ORATAB | awk -F: '{print $2}'`
	REPOS_DB_VERSION=`$REPOS_DB_HOME/OPatch/opatch lsinventory -oh $REPOS_DB_HOME | $GREP 'Oracle Database' | awk '{print $4}'`

	if [[ "$REPOS_DB_VERSION" == "11.2.0.4.0" ]]; then
		RUN_DB_CHECK=1
		echo "$REPOS_DB_VERSION OK"
	fi

	if [[ "$REPOS_DB_VERSION" == "12.1.0.2.0" ]]; then
		echo "$REPOS_DB_VERSION OK"
		RUN_DB_CHECK=1
	fi

	if [[ "$RUN_DB_CHECK" -eq 0 ]]; then
		echo "$REPOS_DB_VERSION not supported, skipping"
	fi
fi


getopts :v VERBOSE_FLAG
if [[ "$VERBOSE_FLAG" == "v" ]]; then
	VERBOSE_CHECKSEC=2
else
	VERBOSE_CHECKSEC=0
fi

# filecreated used to confirm cache files generated correctly and abort if not
filecreated () {
	FILECREATED_CHECKFILE=$1
	if [[ ! -r "${FILECREATED_CHECKFILE}" ]]; then
		echo "Cachefile $FILECREATED_CHECKFILE not created or readable, aborting."
		exit 2
	fi
}


# Gather random seeds for tempfiles
OPATCH_OMS_CACHE_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
OPATCH_CHAINED_AGENT_CACHE_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
OPATCH_REPOS_DB_CACHE_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
OMSPATCHER_OMS_CACHE_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`

# Cache OMS OPatch output
echo -ne "\tOPatch-OMS... "
OPATCH_OMS_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.OPatch.OMS_HOME.$OPATCH_OMS_CACHE_RAND"
$OPATCH lsinv -oh $OMS_HOME > $OPATCH_OMS_CACHE_FILE
filecreated $OPATCH_OMS_CACHE_FILE
echo "OK"

# Cache chained agent OPatch output
echo -ne "\tOPatch-Agent... "
OPATCH_AGENT_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.OPatch.AGENT.$OPATCH_CHAINED_AGENT_CACHE_RAND"
$OPATCH lsinv -oh $AGENT_HOME > $OPATCH_AGENT_CACHE_FILE
filecreated $OPATCH_AGENT_CACHE_FILE
echo "OK"

# Cache repository DB OPatch output
OPATCH_REPOS_DB_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.OPatch.REPOS_DB_HOME.$OPATCH_REPOS_DB_CACHE_RAND"
if [[ "$RUN_DB_CHECK" -eq 1 ]]; then
	echo -ne "\tOPatch-Repos DB... "
	OPATCH_REPOS_DB_CACHE_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
	$REPOS_DB_HOME/OPatch/opatch lsinv -oh $REPOS_DB_HOME > $OPATCH_REPOS_DB_CACHE_FILE
	filecreated $OPATCH_REPOS_DB_CACHE_FILE
	echo "OK"
fi

# Cache OMS OMSPatcher output
echo -ne "\tOMSPatcher-OMS... "
OMSPATCHER_OMS_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.OMSPatcher.OMS_HOME.$OMSPATCHER_OMS_CACHE_RAND"
$OMSPATCHER lspatches -oh $OMS_HOME -jdk $MW_HOME/oracle_common/jdk > $OMSPATCHER_OMS_CACHE_FILE
filecreated $OMSPATCHER_OMS_CACHE_FILE
echo "OK"


$EMCLI sync > /dev/null 2>&1
EMCLI_NOT_LOGGED_IN=$?

if [[ "$EMCLI_NOT_LOGGED_IN" -eq 0 ]]; then
	echo -e "\tEMCLI login... OK"

	echo -e "\tNOTE: If you experience problems with EMCLI integration since version 2.21, grant ACCESS_EMCLI_SQL_LIST_VERB to your EMCLI user."
	EMCLI_AGENTLIST_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
	EMCLI_AGENTPATCHES_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
	EMCLI_AGENTHOMES_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`


	# Cache list of all agents
	echo -ne "\tEMCLI-Agent list... "
	EMCLI_AGENTLIST_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.agentlist.$EMCLI_AGENTLIST_RAND"
#	$EMCLI get_targets | $GREP oracle_emd | awk '{print $4}' > $EMCLI_AGENTLIST_CACHE_FILE
	$EMCLI get_targets -format=name:csv -targets=oracle_emd | $GREP oracle_emd | awk -F, '{print $4}' > $EMCLI_AGENTLIST_CACHE_FILE
	filecreated $EMCLI_AGENTLIST_CACHE_FILE
	echo "OK"

	# Cache list of all patches on agents and their plugins
	echo -ne "\tEMCLI-Agent patches... "
	EMCLI_AGENTPATCHES_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.agenthosts_allpatches.$EMCLI_AGENTPATCHES_RAND"
	$EMCLI list -format="name:script" -noheader -columns="INFO:100" -sql="with patchlist as (select host, listagg(to_char(patch), '; ') within group (order by patch) as patches from ( select unique host, patch from sysman.mgmt\$applied_patches) group by host) select p.patches || ' on ' || p.host AS info from patchlist p where p.host in (select host_name from sysman.mgmt\$target where target_type = 'oracle_emd')" > $EMCLI_AGENTPATCHES_CACHE_FILE
	#$EMCLI list -format="name:script" -noheader -columns="INFO:100" -sql="select patch || ' on ' || host AS info from sysman.mgmt\$applied_patches where host in (select host_name from sysman.mgmt\$target where target_type = 'oracle_emd')" >		 $EMCLI_AGENTPATCHES_CACHE_FILE
#	$EMCLI execute_sql -targets="${REPOS_DB_TARGET_NAME}:oracle_database" -sql="select patch || ' on ' || host from sysman.mgmt\$applied_patches where host in (select host_name from sysman.mgmt\$target where target_type = 'oracle_emd')" > $EMCLI_AGENTPATCHES_CACHE_FILE
	filecreated $EMCLI_AGENTPATCHES_CACHE_FILE
	echo "OK"

	# Cache list of all agent homes
	echo -ne "\tEMCLI-Agent homes... "
	EMCLI_AGENTHOMES_CACHE_FILE="${TMPDIR}/${SCRIPTNAME}_cache.agenthomes.$EMCLI_AGENTHOMES_RAND"
	$EMCLI list -format="name:script" -noheader -columns="INFO:200" -sql="select distinct home_location || ',' || host_name info from sysman.mgmt\$oh_installed_targets where inst_target_type = 'oracle_emd'" > $EMCLI_AGENTHOMES_CACHE_FILE
#	$EMCLI execute_sql -targets="${REPOS_DB_TARGET_NAME}:oracle_database" -sql="select distinct home_location || ',' || host_name from sysman.mgmt\$oh_installed_targets where inst_target_type = 'oracle_emd'" > $EMCLI_AGENTHOMES_CACHE_FILE
	filecreated $EMCLI_AGENTHOMES_CACHE_FILE
	echo "OK"

	EMCLI_CHECK=1
else
	echo "EMCLI login unavailable, skipping... "
fi

echo


# cleantemp used to cleanup leftover temp files
cleantemp () {
	echo -n "Cleaning up temporary files... "
	rm $OPATCH_OMS_CACHE_FILE 2> /dev/null
	rm $OPATCH_AGENT_CACHE_FILE 2> /dev/null
	rm $OPATCH_REPOS_DB_CACHE_FILE 2> /dev/null
	rm $OMSPATCHER_OMS_CACHE_FILE 2> /dev/null

	if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	rm $EMCLI_AGENTLIST_CACHE_FILE 2> /dev/null
	rm $EMCLI_AGENTPATCHES_CACHE_FILE 2> /dev/null
	rm $EMCLI_AGENTHOMES_CACHE_FILE 2> /dev/null
	fi
	echo "done"
}

# apexcheck used to validate installed version of APEX
apexcheck () {
	APEX_CHECK_VERSION=$1

	APEX_COMPARE_MIN=`echo $APEX_CHECK_VERSION | sed 's/\.//g'`

	APEXVERSION=`$EMCLI execute_sql -targets="${REPOS_DB_TARGET_NAME}:oracle_database" -sql="select 'apexver:' || version from dba_registry where comp_name = 'Oracle Application Express'" | $GREP apexver | awk -F: '{print $2}'`

	APEX_COMPARE_CUR=`echo $APEXVERSION | sed 's/\.//g'`

	if [[ $APEX_COMPARE_CUR < $APEX_COMPARE_MIN ]]; then
		echo FAILED
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:APEX @ $REPOS_DB_TARGET_NAME: fails minimum version requirement $APEXVERSION vs $APEX_CHECK_VERSION"
	else
		echo OK
	fi
	return
}

# returnminversion [JS] - given two multidot version strings, return the minimum
# return_min_version used to compare two version-strings in dot-separated format
# missing version-fields will be filled with "0"
function returnminversion() {
	local LV_VERSION_1="$1"
	local LV_VERSION_2="$2"
	declare -a LV_VERS_1_ARR
	LV_VERS_1_ARR=( $(echo "${LV_VERSION_1}" | sed 's/\./ /g') )
	declare -a LV_VERS_2_ARR
	LV_VERS_2_ARR=( $(echo "${LV_VERSION_2}" | sed 's/\./ /g') )

	while [[ ${#LV_VERS_1_ARR[@]} -lt ${#LV_VERS_2_ARR[@]} ]]
	do
		LV_VERS_1_ARR[${#LV_VERS_1_ARR[@]}]=0
	done
	while [[ ${#LV_VERS_2_ARR[@]} -lt ${#LV_VERS_1_ARR[@]} ]]
	do
		LV_VERS_2_ARR[${#LV_VERS_2_ARR[@]}]=0
	done

	local LV_FIELD=0
	while [[ ${LV_FIELD} -lt ${#LV_VERS_1_ARR[@]} ]]
	do
		if [[ "${LV_VERS_1_ARR[${LV_FIELD}]}" -lt "${LV_VERS_2_ARR[${LV_FIELD}]}" ]]
		then
			echo "${LV_VERSION_1}"
			return
		elif [[ "${LV_VERS_1_ARR[${LV_FIELD}]}" -gt "${LV_VERS_2_ARR[${LV_FIELD}]}" ]]
		then
			echo "${LV_VERSION_2}"
			return
		fi
		(( LV_FIELD = LV_FIELD + 1 ))
	done
	echo "${LV_VERSION_1}"
}

# patchercheck used to validate OPatch and/or OMSPatcher versions on a target
patchercheck () {
	PATCHER_CHECK_COMPONENT=$1
	PATCHER_CHECK_OH=$2
	PATCHER_CHECK_VERSION=$3

	if [[ $PATCHER_CHECK_COMPONENT == "OPatch" ]]; then
		PATCHER_RET=`$PATCHER_CHECK_OH/opatch version -jre $MW_HOME/oracle_common/jdk -oh $MW_HOME | $GREP Version | sed 's/.*: //'`
		PATCHER_MINVER=`returnminversion ${PATCHER_RET} ${PATCHER_CHECK_VERSION}`
		#PATCHER_MINVER=`echo -e ${PATCHER_RET}\\\\n${PATCHER_CHECK_VERSION} | sort -t. -g | head -n 1`

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
		PATCHER_RET=`$PATCHER_CHECK_OH/omspatcher version -jre $MW_HOME/oracle_common/jdk -oh $MW_HOME | $GREP 'OMSPatcher Version' | sed 's/.*: //'`
		PATCHER_MINVER=`returnminversion ${PATCHER_RET} ${PATCHER_CHECK_VERSION}`
		#PATCHER_MINVER=`echo -e ${PATCHER_RET}\\\\n${PATCHER_CHECK_VERSION} | sort -t. -g | head -n 1`

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


# sslcheck checks for enabled/disabled status of SSL/TLS protocols using OpenSSL
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

# opatchcheck uses OPatch output cache files to check for patches on repos/agent/middleware targets
opatchcheck () {
	OPATCH_CHECK_COMPONENT=$1
	OPATCH_CHECK_OH=$2
	OPATCH_CHECK_PATCH=$3

	if [[ "$OPATCH_CHECK_COMPONENT" == "ReposDBHome" ]]; then
		OPATCH_RET=`$GREP $OPATCH_CHECK_PATCH $OPATCH_REPOS_DB_CACHE_FILE`
	elif [[ "$OPATCH_CHECK_COMPONENT" == "Agent" ]]; then
		OPATCH_RET=`$GREP $OPATCH_CHECK_PATCH $OPATCH_AGENT_CACHE_FILE`
	else
		OPATCH_RET=`$GREP $OPATCH_CHECK_PATCH $OPATCH_OMS_CACHE_FILE`
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

# opatchplugincheck uses agent OPatch output cache file to check for patches on chained agent. Not used when EMCLI available.
opatchplugincheck () {
	OPATCH_CHECK_COMPONENT=$1
	OPATCH_CHECK_OH=$2
	OPATCH_CHECK_PATCH=$3
	OPATCH_PLUGIN_DIR=$4

	if [[ -d "${OPATCH_CHECK_OH}/plugins/${OPATCH_PLUGIN_DIR}/META-INF" ]]; then
		OPATCH_RET=`$GREP $OPATCH_CHECK_PATCH $OPATCH_AGENT_CACHE_FILE`
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


# check OMS OMSPatcher cache file for existence of a patch
# should edit this to make sure ALL oms side system patches are installed, not just any one of three
# but should also not check 13.2.3 unless at least one 13.2.3 plugin is installed
# ditto for 13.2.2 and presence of 13.2.2 plugins
omspatchercheck () {
	OMSPATCHER_CHECK_COMPONENT=$1
	OMSPATCHER_CHECK_OH=$2
	OMSPATCHER_CHECK_PATCH=$3

	if [[ "$OMSPATCHER_CHECK_PATCH" -eq "$OMSSIDE1322" || "$OMSPATCHER_CHECK_PATCH" -eq "$OMSSIDE1321" || "$OMSPATCHER_CHECK_PATCH" -eq "$OMSSIDE1323" || "$OMSPATCHER_CHEcK_PATCH" -eq "$OMSSIDE1324" ]]; then
		# special case handling for 13.2.1 plugin bundle update when 13.2.2 plugins have been installed & vice versa
		OMSPATCHER_RET=`$GREP -e $OMSSIDE1322 -e $OMSSIDE1321 -e $OMSSIDE1323 -e $OMSSIDE1324 $OMSPATCHER_OMS_CACHE_FILE`
	else
		OMSPATCHER_RET=`$GREP $OMSPATCHER_CHECK_PATCH $OMSPATCHER_OMS_CACHE_FILE`
	fi


	if [[ -z "$OMSPATCHER_RET" ]]; then
		echo FAILED
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OMSPATCHER_CHECK_COMPONENT @ ${OMSPATCHER_CHECK_OH}:Patch $OMSPATCHER_CHECK_PATCH not found"
	else
		echo OK
	fi

	test $VERBOSE_CHECKSEC -ge 2 && echo $OMSPATCHER_RET
}

# combinedcertcheck checks for presence of a self-signed or demo certificate on a component
combinedcertcheck () {
	CERTCHECK_CHECK_COMPONENT=$1
	CERTCHECK_CHECK_HOST=$2
	CERTCHECK_CHECK_PORT=$3

	echo -ne "\tChecking certificate at $CERTCHECK_CHECK_COMPONENT ($CERTCHECK_CHECK_HOST:$CERTCHECK_CHECK_PORT, protocol $OPENSSL_CERTCHECK_PROTOCOL)... "

	OPENSSL_RESULT="`echo Q | $OPENSSL s_client -prexit -connect $CERTCHECK_CHECK_HOST:$CERTCHECK_CHECK_PORT -$OPENSSL_CERTCHECK_PROTOCOL 2>&1`"
	OPENSSL_CHECK_FAILED=`echo "${OPENSSL_RESULT}" | $GREP -ci ":wrong version number:"`
	OPENSSL_SELFSIGNED_COUNT=`echo "${OPENSSL_RESULT}" | $GREP -ci "self signed certificate"`
	OPENSSL_DEMO_COUNT=`echo "${OPENSSL_RESULT}" | $GREP -ci "issuer=/C=US/ST=MyState/L=MyTown/O=MyOrganization/OU=FOR TESTING ONLY/CN"`

	if [[ $OPENSSL_CHECK_FAILED -ne "0" ]]; then
		echo FAILED - SSL handshake failed
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$CERTCHECK_CHECK_COMPONENT @ ${CERTCHECK_CHECK_HOST}:${CERTCHECK_CHECK_PORT} SSL handshake failed"
	elif [[ $OPENSSL_SELFSIGNED_COUNT -ne "0" ]]; then
		echo FAILED - Found self-signed certificate
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$CERTCHECK_CHECK_COMPONENT @ ${CERTCHECK_CHECK_HOST}:${CERTCHECK_CHECK_PORT} found self-signed certificate"
	elif [[ $OPENSSL_DEMO_COUNT -ne "0" ]]; then
		echo FAILED - Found demonstration certificate
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$CERTCHECK_CHECK_COMPONENT @ ${CERTCHECK_CHECK_HOST}:${CERTCHECK_CHECK_PORT} found demonstration certificate"
	else
		echo OK
	fi
}

# ciphercheck confirms LOW/MEDIUM strength ciphers not accepted, and HIGH strength ciphers accepted, on a component
ciphercheck () {
	OPENSSL_CHECK_COMPONENT=$1
	OPENSSL_CHECK_HOST=$2
	OPENSSL_CHECK_PORT=$3
	CIPHERCHECK_SECTION=$4

	echo -ne "\t($CIPHERCHECK_SECTION) Checking LOW strength ciphers on $OPENSSL_CHECK_COMPONENT ($OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT, protocol $OPENSSL_CERTCHECK_PROTOCOL)..."

	# Added 20170425, issue #4: Wrong detection of LOW security ciphers on agents
	#
	# Some OpenSSL deployments do not have any LOW strength ciphers available
	#
	# $ openssl ciphers LOW
	# Error in cipher list
	# 140665824761672:error:1410D0B9:SSL routines:SSL_CTX_set_cipher_list:no cipher match:ssl_lib.c:1314:

#	OPENSSL_CHECK_NO_LOW_CIPHERS=`$OPENSSL ciphers LOW 2>&1 | $GREP -c "Error in cipher list"`
	if [[ $OPENSSL_CHECK_NO_LOW_CIPHERS -eq "1" ]]; then
		echo -e "\tN/A - OpenSSL LOW strength ciphers not available"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Unable to check LOW strength ciphers, not supported by installed OpenSSL"
	else
		OPENSSL_LOW_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$OPENSSL_CERTCHECK_PROTOCOL -cipher LOW 2>&1 | $GREP Cipher | uniq | $GREP -c 0000`

		if [[ $OPENSSL_LOW_RETURN -eq "0" ]]; then
			echo -e "\tFAILED - PERMITS LOW STRENGTH CIPHER CONNECTIONS"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Permits LOW strength ciphers"
		else
			echo -e "\tOK"
		fi
	fi

	echo -ne "\t($CIPHERCHECK_SECTION) Checking MEDIUM strength ciphers on $OPENSSL_CHECK_COMPONENT ($OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT)..."
	OPENSSL_MEDIUM_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$OPENSSL_CERTCHECK_PROTOCOL -cipher MEDIUM 2>&1 | $GREP Cipher | uniq | $GREP -c 0000`

	if [[ $OPENSSL_MEDIUM_RETURN -eq "0" ]]; then
		echo -e "\tFAILED - PERMITS MEDIUM STRENGTH CIPHER CONNECTIONS"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Permits MEDIUM strength ciphers"
	else
		echo -e "\tOK"
	fi


	echo -ne "\t($CIPHERCHECK_SECTION) Checking HIGH strength ciphers on $OPENSSL_CHECK_COMPONENT ($OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT)..."
	OPENSSL_HIGH_RETURN=`echo Q | $OPENSSL s_client -prexit -connect $OPENSSL_CHECK_HOST:$OPENSSL_CHECK_PORT -$OPENSSL_CERTCHECK_PROTOCOL -cipher HIGH 2>&1 | $GREP Cipher | uniq | $GREP -c 0000`

	if [[ $OPENSSL_HIGH_RETURN -eq "0" ]]; then
		echo -e "\tOK"
	else
		echo -e "\tFAILED - CANNOT CONNECT WITH HIGH STRENGTH CIPHER"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$OPENSSL_CHECK_COMPONENT @ $OPENSSL_CHECK_HOST:${OPENSSL_CHECK_PORT}:Rejects HIGH strength ciphers"
	fi
	echo
}


# paramcheck validates parameters in the repository DB configuration files
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

	PARAMCHECK_RETURN=`$GREP $WHICH_PARAM $WHICH_ORACLE_HOME/network/admin/$WHICH_FILE | $GREP -v '^#' | awk -F= '{print $2}' | sed -e 's/\s//g'`
	if [[ "$WHICH_PARAM" == "SSL_VERSION" ]]; then
		if [[ "$PARAMCHECK_RETURN" == "1.2" ]]; then
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

# javacheck checks the version of java used by a component on the local host
javacheck () {
	WHICH_JAVA=$1
	JAVA_DIR=$2
	JAVA_VER=$3

	JAVACHECK_RETURN=`$JAVA_DIR/bin/java -version 2>&1 | $GREP version | awk '{print $3}' | sed -e 's/"//g'`

	if [[ "$JAVACHECK_RETURN" == "$JAVA_VER" ]]; then
		echo -e "\tOK"
	else
		echo -e "\tFAILED"
		FAIL_COUNT=$((FAIL_COUNT+1))
		FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_JAVA Java in ${JAVA_DIR}:Found incorrect version $JAVACHECK_RETURN vs $JAVA_VER"
	fi
	test $VERBOSE_CHECKSEC -ge 2 && echo $JAVACHECK_RETURN
}


# emclijavacheck uses emcli execute_sql to identify the agent home directory and execute_hostcmd to validate java version
emclijavacheck () {
	JAVA_VERSION=$1

	for curagent in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		THEHOST=`echo $curagent | sed -e 's/:.*$//'`
		echo -ne "\n\t(5b) Agent $curagent JAVA VERSION $JAVA_VERSION... "
		EMCLIJAVACHECK_GETHOME=`$GREP $THEHOST $EMCLI_AGENTHOMES_CACHE_FILE | awk -F, '{print $1}'`
		EMCLIJAVACHECK_GETHOME=`echo $EMCLIJAVACHECK_GETHOME | sed -e 's/\\\\/\\\\\\\\/g'`
		EMCLIJAVACHECK_GETVER=`$EMCLI execute_hostcmd -cmd="$EMCLIJAVACHECK_GETHOME/jdk/bin/java -version" -targets="$THEHOST:host" | $GREP version | awk '{print $3}' | sed -e 's/"//g'`

		if [[ "$EMCLIJAVACHECK_GETVER" == "$JAVA_CHECK_VERSION" ]]; then
			echo -e "\tOK"
		elif [[ "$EMCLIJAVACHECK_GETVER" == "" ]]; then
			echo -e "\tFAILED, NO PREFERRED CREDENTIALS"
			EMCLIACCTFAILUREFLAG=1
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:Java in $THEHOST:$EMCLIJAVACHECK_GETHOME/jdk:PREFERRED CREDENTIALS NOT SET"
		else
			echo -e "\tFAILED"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:Java in $THEHOST:$EMCLIJAVACHECK_GETHOME/jdk:Found incorrect version $EMCLIJAVACHECK_GETVER vs $JAVA_CHECK_VERSION"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $EMCLIJAVACHECK_GETVER
	done
}

# emcliagentbundlecheck uses the agent patch list cache files to check for existence of a patch on an agent
emcliagentbundlecheck() {
	EMCLIAGENTBUNDLE_SECTION=$1
	EMCLIAGENTBUNDLE_PATCH=$2
	EMCLIAGENTBUNDLE_DESC=$3

	for i in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		THEHOST=`echo $i | sed -e 's/:.*$//'`
		echo -ne "\n\t($EMCLIAGENTBUNDLE_SECTION) Agent $i $EMCLIAGENTBUNDLE_DESC ($EMCLIAGENTBUNDLE_PATCH)... "

		EMCLIAGENTBUNDLE_QUERY_RET=`$GREP $THEHOST $EMCLI_AGENTPATCHES_CACHE_FILE | $GREP -c $EMCLIAGENTBUNDLE_PATCH`

		if [[ "$EMCLIAGENTBUNDLE_QUERY_RET" -eq 1 ]]; then
			echo -e "\tOK"
		else
			echo -e "\tFAILED"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$EMCLIAGENTBUNDLE_PATCH missing on $i"
		fi
	done
}

# emclipluginpatchpresent uses the agent plugins cache file and agent patch cache file to check for presence
# of a plugin on an agent, as well as presence of specific patch on an agent
emclipluginpatchpresent () {
	WHICH_TARGET_TYPE=$1
	WHICH_PLUGIN=$2
	WHICH_PLUGIN_TYPE=$3
	WHICH_PLUGIN_VERSION=$4
	WHICH_PATCH=$5
	WHICH_LABEL=$6
	WHICH_PATCH_DESC=$7
	EMCLI_PLUGINPATCHPRESENT_HOST=`echo $curagent | sed 's/:.*$//'`

	echo -ne "\n\t(${SECTION_NUM}${WHICH_LABEL}) $WHICH_PATCH_DESC @ $curagent ($WHICH_PATCH)... "

	PLUGIN_EXISTS=`$GREP $WHICH_PLUGIN $EMCLICHECK_HOSTPLUGINS_CACHEFILE | sed "s/^.*$WHICH_PLUGIN/$WHICH_PLUGIN/"`

	if [[ -z "$PLUGIN_EXISTS" ]]; then
		echo "OK - plugin not installed"
	else
		if [[ "$WHICH_PLUGIN_TYPE" == "discovery" ]]; then
			CUR_PLUGIN_VERSION="${WHICH_PLUGIN_VERSION}\*"
		else
			CUR_PLUGIN_VERSION="${WHICH_PLUGIN_VERSION}$"
		fi

		for j in $PLUGIN_EXISTS; do
			EMCLICHECK_RETURN=""
			EMCLICHECK_FOUND_VERSION=`echo $j | $GREP -c $CUR_PLUGIN_VERSION`
			if [[ $EMCLICHECK_FOUND_VERSION > 0 ]]; then
				EMCLICHECK_RETURN="OK"
				break
			fi
		done

		# OK at this point simply means plugin home exists on the agent
		# Now check for existence of patch

		if [[ "$EMCLICHECK_RETURN" == "OK" ]]; then
			EMCLICHECK_QUERY_RET=`$GREP $EMCLI_PLUGINPATCHPRESENT_HOST $EMCLI_AGENTPATCHES_CACHE_FILE | $GREP -c $WHICH_PATCH`

			if [[ "$EMCLICHECK_QUERY_RET" -eq 1 ]]; then
				echo -e "\tOK"
			else
				echo -e "\tFAILED"
				FAIL_COUNT=$((FAIL_COUNT+1))
				FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:$WHICH_PATCH missing in $WHICH_PLUGIN on $EMCLI_PLUGINPATCHPRESENT_HOST"
			fi
		else
			echo -e "\tOK - plugin not installed"
		fi
	fi

#	test $VERBOSE_CHECKSEC -ge 2 && echo $EMCLICHECK_RETURN
}

# emcliagentbundlepluginpatchcheck caches agent plugin lists and calls emclipluginpatchpresent to check patch presence
emcliagentbundlepluginpatchcheck () {
	SECTION_NUM=$1

	for curagent in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		EMCLICHECK_RETURN="FAILED"
		EMCLICHECK_FOUND_VERSION=0
		EMCLICHECK_RAND=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
		EMCLICHECK_HOSTPLUGINS_CACHEFILE="plugins_${curagent}_cache.${EMCLICHECK_RAND}"

		$EMCLI list_plugins_on_agent -agent_names="${curagent}" -include_discovery > $EMCLICHECK_HOSTPLUGINS_CACHEFILE

		emclipluginpatchpresent oracle_emd oracle.sysman.db agent 13.2.1.0.0 $DBPLG1321MONPATCH a "$DBPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.db agent 13.2.2.0.0 $DBPLG1322MONPATCH a "$DBPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.db discovery 13.2.1.0.0 $DBPLG1321DISCPATCH b "$DBPLG1321DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.db discovery 13.2.2.0.0 $DBPLG1322DISCPATCH b "$DBPLG1322DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emas agent 13.2.1.0.0 $FMWPLG1321MONPATCH c "$FMWPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emas agent 13.2.2.0.0 $FMWPLG1322MONPATCH c "$FMWPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emas agent 13.2.3.0.0 $FMWPLG1323MONPATCH c "$FMWPLG1323MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emas discovery 13.2.1.0.0 $FMWPLG1321DISCPATCH d "$FMWPLG1321DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emas discovery 13.2.2.0.0 $FMWPLG1322DISCPATCH d "$FMWPLG1322DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emas discovery 13.2.3.0.0 $FMWPLG1323DISCPATCH d "$FMWPLG1323DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.si agent 13.2.1.0.0 $SIPLG1321MONPATCH e "$SIPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.si agent 13.2.2.0.0 $SIPLG1322MONPATCH e "$SIPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.si agent 13.2.3.0.0 $SIPLG1323MONPATCH e "$SIPLG1323MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.beacon agent 13.2.0.0.0 $BEACONPLG1320PATCH f "$BEACONPLG1320DESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.xa discovery 13.2.1.0.0 $EXAPLG1321DISCPATCH g "$EXAPLG1321DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.xa discovery 13.2.2.0.0 $EXAPLG1322DISCPATCH g "$EXAPLG1322DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.xa agent 13.2.2.0.0 $EXAPLG1322MONPATCH g "$EXAPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.xa agent 13.2.1.0.0 $EXAPLG1321MONPATCH h "$EXAPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emfa agent 13.2.1.0.0 $FMWAPPSPLG1321MONPATCH i "$FMWAPPSPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emfa agent 13.2.2.0.0 $FMWAPPSPLG1322MONPATCH i "$FMWAPPSPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emfa agent 13.2.3.0.0 $FMWAPPSPLG1323MONPATCH i "$FMWAPPSPLG1323MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emfa agent 13.2.1.0.0 $FMWAPPSPLG1321DISCPATCH j "$FMWAPPSPLG1321DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.emfa agent 13.2.2.0.0 $FMWAPPSPLG1322DISCPATCH j "$FMWAPPSPLG1322DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vi agent 13.2.1.0.0 $OVIPLG1321MONPATCH k "$OVIPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vi agent 13.2.2.0.0 $OVIPLG1322MONPATCH k "$OVIPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vi agent 13.2.3.0.0 $OVIPLG1323MONPATCH k "$OVIPLG1323MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vi discovery 13.2.1.0.0 $OVIPLG1321DISCPATCH l "$OVIPLG1321DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vi discovery 13.2.2.0.0 $OVIPLG1322DISCPATCH l "$OVIPLG1322DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vi discovery 13.2.3.0.0 $OVIPLG1323DISCPATCH l "$OVIPLG1323DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vt agent 13.2.1.0.0 $VIRTPLG1321MONPATCH m "$VIRTPLG1321MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vt agent 13.2.2.0.0 $VIRTPLG1322MONPATCH m "$VIRTPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vt agent 13.2.3.0.0 $VIRTPLG1323MONPATCH m "$VIRTPLG1323MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vt discovery 13.2.1.0.0 $VIRTPLG1321DISCPATCH n "$VIRTPLG1321DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.vt discovery 13.2.3.0.0 $VIRTPLG1323DISCPATCH n "$VIRTPLG1323DISCDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.csm agent 13.2.2.0.0 $CSMPLG1322MONPATCH n "$CSMPLG1322MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.csm agent 13.2.3.0.0 $CSMPLG1323MONPATCH n "$CSMPLG1323MONDESC"
		emclipluginpatchpresent oracle_emd oracle.sysman.am agent 13.2.2.0.0 $ZDLRAPLG1322MONPATCH n "$ZDLRAPLG1322MONDESC"

		(( SECTION_NUM+=1 ))

		rm $EMCLICHECK_HOSTPLUGINS_CACHEFILE
	done
}

# emcliagentselfsignedcerts uses the agent list cache file to identify agents and check for self signed certs at each endpoint
emcliagentselfsignedcerts() {
	for curagent in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		EMCLIAGENTSELFSIGNEDCERTS_CHECK_HOST=`echo $curagent | sed 's/:.*$//'`
		EMCLIAGENTSELFSIGNEDCERTS_CHECK_PORT=`echo $curagent | sed 's/^.*://'`

		combinedcertcheck Agent $EMCLIAGENTSELFSIGNEDCERTS_CHECK_HOST $EMCLIAGENTSELFSIGNEDCERTS_CHECK_PORT
		#certcheck Agent $EMCLIAGENTSELFSIGNEDCERTS_CHECK_HOST $EMCLIAGENTSELFSIGNEDCERTS_CHECK_PORT
	done
}

# emcliagentdemocerts uses the agent list cache file to identify agents and check for use of demonstration certs at each endpoint
emcliagentdemocerts() {
	for curagent in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		EMCLIAGENTDEMOCERTS_CHECK_HOST=`echo $curagent | sed 's/:.*$//'`
		EMCLIAGENTDEMOCERTS_CHECK_PORT=`echo $curagent | sed 's/^.*://'`

		democertcheck Agent $EMCLIAGENTDEMOCERTS_CHECK_HOST $EMCLIAGENTDEMOCERTS_CHECK_PORT
	done
}

# emcliagentprotocols uses the agent list cache file to identify agents and check SSL/TLS protocols on each endpoint
emcliagentprotocols() {
	EMCLIAGENTPROTOCOLS_SECTION=$1
	EMCLIAGENTPROTOCOLS_CHECK_PROTO=$2
	OPENSSL_AVAILABLE_OR_DISABLED="disabled"

	for curagent in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		EMCLIAGENTPROTOCOLS_CHECK_HOST=`echo $curagent | sed 's/:.*$//'`
		EMCLIAGENTPROTOCOLS_CHECK_PORT=`echo $curagent | sed 's/^.*://'`

		sslcheck Agent $EMCLIAGENTPROTOCOLS_CHECK_HOST $EMCLIAGENTPROTOCOLS_CHECK_PORT $EMCLIAGENTPROTOCOLS_CHECK_PROTO
	done
}

# emcliagentciphers uses the agent list cache file to identify agents and check ciphersuites available on each endpoint
emcliagentciphers() {
	EMCLIAGENTCIPHERS_SECTION=$1

	for curagent in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		EMCLIAGENTCIPHERS_CHECK_HOST=`echo $curagent | sed 's/:.*$//'`
		EMCLIAGENTCIPHERS_CHECK_PORT=`echo $curagent | sed 's/^.*://'`

		ciphercheck Agent $EMCLIAGENTCIPHERS_CHECK_HOST $EMCLIAGENTCIPHERS_CHECK_PORT $EMCLIAGENTCIPHERS_SECTION
	done
}

# emcliagentopatch uses execute_sql and execute_hostcmd to check the OPatch version on every agent
emcliagentopatch() {
	SECTION=$1
	AGENT_OPATCH_VERSION=$2

	for i in `cat $EMCLI_AGENTLIST_CACHE_FILE`; do
		THEHOST=`echo $i | sed -e 's/:.*$//'`
		echo -ne "\n\t($SECTION) Agent $i ORACLE_HOME OPatch VERSION $AGENT_OPATCH_VERSION... "

		EMCLIAGENTOPATCHCHECK_GETHOME=`$GREP $THEHOST $EMCLI_AGENTHOMES_CACHE_FILE | awk -F, '{print $1}'`
		EMCLIAGENTOPATCHCHECK_GETHOME=`echo $EMCLIAGENTOPATCHCHECK_GETHOME | sed -e 's/\\\\/\\\\\\\\/g'`
		EMCLIAGENTOPATCHCHECK_GETVER=`$EMCLI execute_hostcmd -cmd="$EMCLIAGENTOPATCHCHECK_GETHOME/OPatch/opatch version -jre $EMCLIAGENTOPATCHCHECK_GETHOME/oracle_common/jdk" -targets="$THEHOST:host" | $GREP Version | sed 's/.*: //'`
		EMCLIAGENTOPATCHCHECK_MINVER=`returnminversion ${EMCLIAGENTOPATCHCHECK_GETVER} ${AGENT_OPATCH_VERSION}`

		#if [[ "$EMCLIAGENTOPATCHCHECK_GETVER" == "$AGENT_OPATCH_VERSION" ]]; then
		if [[ "$EMCLIAGENTOPATCHCHECK_MINVER" == "$AGENT_OPATCH_VERSION" ]]; then
			echo -e "\tOK"
		elif [[ "$EMCLIAGENTOPATCHCHECK_MINVER" == "" ]]; then
			EMCLIACCTFAILUREFLAG=1
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:OPatch in $THEHOST:$EMCLIAGENTOPATCHCHECK_GETHOME/OPatch:PREFERRED CREDENTIALS NOT SET"
		else
			echo -e "\tFAILED"
			FAIL_COUNT=$((FAIL_COUNT+1))
			FAIL_TESTS="${FAIL_TESTS}\\n$FUNCNAME:OPatch in $THEHOST:$EMCLIAGENTOPATCHCHECK_GETHOME/OPatch: fails minimum version requirement $EMCLIAGENTOPATCHCHECK_GETVER vs $AGENT_OPATCH_VERSION"
		fi
		test $VERBOSE_CHECKSEC -ge 2 && echo $EMCLIAGENTOPATCHCHECK_GETVER
	done
}


### MAIN SCRIPT HERE



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
if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking SSLv2 on all agents\n"
	emcliagentprotocols 1a ssl2
fi

echo -e "\n\t(1b) Forbid SSLv3 connections"
sslcheck Agent $OMSHOST $PORT_AGENT ssl3
sslcheck BIPublisher $OMSHOST $PORT_BIP ssl3
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER ssl3
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS ssl3
sslcheck OMSconsole $OMSHOST $PORT_OMS ssl3
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA ssl3
sslcheck OMSupload $OMSHOST $PORT_UPL ssl3
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER ssl3
if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking SSLv3 on all agents\n"
	emcliagentprotocols 1b ssl3
fi

echo -e "\n\t(1c) $OPENSSL_PERMIT_FORBID_NON_TLS1_2 TLSv1 connections"
sslcheck Agent $OMSHOST $PORT_AGENT tls1
sslcheck BIPublisher $OMSHOST $PORT_BIP tls1
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER tls1
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS tls1
sslcheck OMSconsole $OMSHOST $PORT_OMS tls1
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA tls1
sslcheck OMSupload $OMSHOST $PORT_UPL tls1
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER tls1
if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking TLSv1 on all agents\n"
	emcliagentprotocols 1c tls1
fi

echo -e "\n\t(1d) $OPENSSL_PERMIT_FORBID_NON_TLS1_2 TLSv1.1 connections"
sslcheck Agent $OMSHOST $PORT_AGENT tls1_1
sslcheck BIPublisher $OMSHOST $PORT_BIP tls1_1
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER tls1_1
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS tls1_1
sslcheck OMSconsole $OMSHOST $PORT_OMS tls1_1
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA tls1_1
sslcheck OMSupload $OMSHOST $PORT_UPL tls1_1
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER tls1_1
if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking TLSv1.1 on all agents\n"
	emcliagentprotocols 1d tls1_1
fi

echo -e "\n\t(1e) Permit TLSv1.2 connections"
sslcheck Agent $OMSHOST $PORT_AGENT tls1_2
sslcheck BIPublisher $OMSHOST $PORT_BIP tls1_2
sslcheck NodeManager $OMSHOST $PORT_NODEMANAGER tls1_2
sslcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS tls1_2
sslcheck OMSconsole $OMSHOST $PORT_OMS tls1_2
sslcheck OMSproxy $OMSHOST $PORT_OMS_JAVA tls1_2
sslcheck OMSupload $OMSHOST $PORT_UPL tls1_2
sslcheck WLSadmin $OMSHOST $PORT_ADMINSERVER tls1_2
if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking TLSv1.2 on all agents\n"
	emcliagentprotocols 1e tls1_2
fi

echo -e "\n(2) Checking supported ciphers at SSL/TLS endpoints (see notes 2138391.1, 1067411.1)"
ciphercheck Agent $OMSHOST $PORT_AGENT 2a
ciphercheck BIPublisher $OMSHOST $PORT_BIP 2b
ciphercheck NodeManager $OMSHOST $PORT_NODEMANAGER 2c
ciphercheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS 2d
ciphercheck OMSconsole $OMSHOST $PORT_OMS 2e
ciphercheck OMSproxy $OMSHOST $PORT_OMS_JAVA 2f
ciphercheck OMSupload $OMSHOST $PORT_UPL 2g
ciphercheck WLSadmin $OMSHOST $PORT_ADMINSERVER 2h
if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking supported ciphers on all agents\n"
	emcliagentciphers 2i
fi

echo -e "\n(3) Checking self-signed and demonstration certificates at SSL/TLS endpoints (see notes 2202569.1, 1367988.1, 1914184.1, 2213661.1, 2220788.1, 123033.1, 1937457.1)"

echo -e "\n\t(3a) Checking for self-signed and demonstration certificates on OMS components"
combinedcertcheck Agent $OMSHOST $PORT_AGENT
combinedcertcheck BIPublisherOHS $OMSHOST $PORT_BIP_OHS
combinedcertcheck BIPublisher $OMSHOST $PORT_BIP
combinedcertcheck NodeManager $OMSHOST $PORT_NODEMANAGER
combinedcertcheck OMSconsole $OMSHOST $PORT_OMS
combinedcertcheck OMSproxy $OMSHOST $PORT_OMS_JAVA
combinedcertcheck OMSupload $OMSHOST $PORT_UPL
combinedcertcheck WLSadmin $OMSHOST $PORT_ADMINSERVER

if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\t(3b) Checking for self-signed/demonstration certificates on all agents\n"
	emcliagentselfsignedcerts
fi

echo -e "\n(4) Checking EM13c Oracle home patch levels against $PATCHDATE baseline (see notes $PATCHNOTE, 822485.1, 1470197.1)"

if [[ $RUN_DB_CHECK -eq 1 ]]; then

	if [[ "$REPOS_DB_VERSION" == "12.1.0.2.0" ]]; then
		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) $DB12102PSUDESC... "
		opatchcheck ReposDBHome $REPOS_DB_HOME $DB12102PSUPATCH

		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) $DB12102JAVADESC... "
		opatchcheck ReposDBHome $REPOS_DB_HOME $DB12102JAVAPATCH

		echo -ne "\n\t(4a) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) OCW Patch Set Update : 12.1.0.2.190716 (29509318)... "
		opatchcheck ReposDBHome $REPOS_DB_HOME 29509318

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

	if [[ "$EMCLI_CHECK" -eq 1 ]]; then
		echo -ne "\n\t(4b) OMS REPOSITORY DATABASE HOME ($REPOS_DB_HOME) APEX version... "
		#apexcheck 5.0.4.00.12
		apexcheck 5.1.4.00.08
	fi
fi

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) $OMSPSUDESC... "
omspatchercheck OMS $OMS_HOME $OMSPSUPATCH

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) TRACKING BUG TO REGISTER META VERSION FROM PS4 AND 13.1 BUNDLE PATCHES IN 13.2 (SYSTEM PATCH) (23603592)... "
omspatchercheck OMS $OMS_HOME 23603592

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) MERGE REQUEST ON TOP OF 12.1.3.0.0 FOR BUGS 24571979 24335626 (25322055)... "
omspatchercheck OMS $OMS_HOME 25322055

#echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) MERGE REQUEST ON TOP OF 12.1.3.0.0 FOR BUGS 22557350 19901079 20222451 (24329181)... "
#omspatchercheck OMS $OMS_HOME 24329181

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) $OHSSPUDESC... "
omspatchercheck OMS $OMS_HOME $OHSSPUPATCH

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) OPSS BUNDLE PATCH 12.1.3.0.170418 (22748215)... "
omspatchercheck OMS $OMS_HOME 22748215

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) ENTERPRISE MANAGER FOR OMS PLUGINS 13.2.1.0.$OMSSIDE1321DATE (for 13.2.1 plugins) ($OMSSIDE1321)... "
omspatchercheck OMS $OMS_HOME $OMSSIDE1321

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) ENTERPRISE MANAGER FOR OMS PLUGINS 13.2.2.0.$OMSSIDE1322DATE (for 13.2.2 plugins) ($OMSSIDE1322)... "
omspatchercheck OMS $OMS_HOME $OMSSIDE1322

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) ENTERPRISE MANAGER FOR OMS PLUGINS 13.2.3.0.$OMSSIDE1323DATE (for 13.2.3 plugins) ($OMSSIDE1323)... "
omspatchercheck OMS $OMS_HOME $OMSSIDE1323

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) ENTERPRISE MANAGER FOR OMS PLUGINS 13.2.4.0.$OMSSIDE1324DATE (for 13.2.4 plugins) ($OMSSIDE1324)... "
omspatchercheck OMS $OMS_HOME $OMSSIDE1324

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) $WLSPSUDESC... "
opatchcheck WLS $OMS_HOME $WLSPSUPATCH

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) TOPLINK SECURITY PATCH UPDATE CPUJUL2016 (24327938)... "
opatchcheck WLS $OMS_HOME 24327938

echo -ne "\n\t(4c) OMS HOME ($OMS_HOME) OSS SECURITY PATCH UPDATE 12.1.3.0.0 (CPUOCT2017) (26591558)... "
opatchcheck WLS $OMS_HOME 26591558


if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tUsing EMCLI check for agent bundle patch on all agents"
	emcliagentbundlecheck 4d $AGTBUNDLEPATCH "$AGTBUNDLEDESC"
else
	echo -e "\n\tNot logged in to EMCLI, will only check agent bundle patch on local host."
	echo -ne "\n\t(4d) OMS CHAINED AGENT HOME ($AGENT_HOME) $AGTBUNDLEDESC... "
	opatchcheck Agent $AGENT_HOME $AGTBUNDLEPATCH
fi




echo -e "\n(5) Checking EM13cR2 Java patch levels against $PATCHDATE baseline (see notes 1506916.1, 2241373.1, 2241358.1, and patch 13079846)"

echo -ne "\n\t(5a) Common Java ($OMS_HOME/oracle_common/jdk) JAVA SE JDK VERSION $JAVA_CHECK_VERSION (13079846)... "
javacheck JAVA $OMS_HOME/oracle_common/jdk "$JAVA_CHECK_VERSION"

if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tUsing EMCLI to check Java patch levels on all agents"
	emclijavacheck "$JAVA_CHECK_VERSION"
else
	echo -e "\n\tNot logged in to EMCLI, will only check Java patch levels on local host."
	echo -ne "\n\t(5b) OMS Chained Agent Java ($AGENT_HOME/oracle_common/jdk) JAVA SE JDK VERSION $JAVA_CHECK_VERSION (13079846)... "
	javacheck JAVA $AGENT_HOME/oracle_common/jdk "$JAVA_CHECK_VERSION"
fi




echo -e "\n(6) Checking EM13cR2 OPatch/OMSPatcher patch levels against $PATCHDATE requirements (see patch 25197714 README, patches 6880880 and 19999993)"

echo -ne "\n\t(6a) OMS OPatch ($OMS_HOME/OPatch) VERSION $OPATCH_CHECK_VERSION or newer... "
patchercheck OPatch $OMS_HOME/OPatch $OPATCH_CHECK_VERSION

echo -ne "\n\t(6b) OMSPatcher ($OMS_HOME/OPatch) VERSION $OMSPATCHER_CHECK_VERSION or newer... "
patchercheck OMSPatcher $OMS_HOME/OMSPatcher $OMSPATCHER_CHECK_VERSION

if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -e "\n\tChecking OPatch patch levels on all agents"
	emcliagentopatch 6c $OPATCH_AGENT_CHECK_VERSION
fi


if [[ "$EMCLI_CHECK" -eq 1 ]]; then
	echo -ne "\n(7) Agent plugin bundle patch checks on all agents... "
	emcliagentbundlepluginpatchcheck 7
else
	echo -e "\n(7) Not logged in to EMCLI. Skipping EMCLI-based checks. To enable EMCLI checks, login to EMCLI"
	echo	"	with an OEM user that has configured default normal database credentials and default host"
	echo	"	credentials for your repository database target, then run this script again."

	echo -ne "\n\t(7a) OMS CHAINED AGENT HOME ($AGENT_HOME) $DBPLG1321MONDESC ($DBPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $DBPLG1321MONPATCH oracle.sysman.db.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7b) OMS CHAINED AGENT HOME ($AGENT_HOME) $DBPLG1321DISCDESC ($DBPLG1321DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $DBPLG1321DISCPATCH oracle.sysman.db.discovery.plugin_13.2.1.0.0

	echo -ne "\n\t(7a) OMS CHAINED AGENT HOME ($AGENT_HOME) $DBPLG1322MONDESC ($DBPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $DBPLG1322MONPATCH oracle.sysman.db.agent.plugin_13.2.2.0.0

	echo -ne "\n\t(7b) OMS CHAINED AGENT HOME ($AGENT_HOME) $DBPLG1322DISCDESC ($DBPLG1322DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $DBPLG1322DISCPATCH oracle.sysman.db.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7c) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWPLG1321MONDESC ($FMWPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1321MONPATCH oracle.sysman.emas.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7c) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWPLG1322MONDESC ($FMWPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1322MONPATCH oracle.sysman.emas.agent.plugin_13.2.2.0.0

	echo -ne "\n\t(7c) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWPLG1323MONDESC ($FMWPLG1323MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1323MONPATCH oracle.sysman.emas.agent.plugin_13.2.3.0.0

	echo -ne "\n\t(7d) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWPLG1321DISCDESC ($FMWPLG1321DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1321DISCPATCH oracle.sysman.emas.discovery.plugin_13.2.1.0.0

	echo -ne "\n\t(7d) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWPLG1322DISCDESC ($FMWPLG1322DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1322DISCPATCH oracle.sysman.emas.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7d) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWPLG1323DISCDESC ($FMWPLG1323DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1323DISCPATCH oracle.sysman.emas.discovery.plugin_13.2.3.0.0

	echo -ne "\n\t(7e) OMS CHAINED AGENT HOME ($AGENT_HOME) $SIPLG1321MONDESC ($SIPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $SIPLG1321MONPATCH oracle.sysman.si.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7e) OMS CHAINED AGENT HOME ($AGENT_HOME) $SIPLG1322MONDESC ($SIPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $SIPLG1322MONPATCH oracle.sysman.si.agent.plugin_13.2.2.0.0

	echo -ne "\n\t(7e) OMS CHAINED AGENT HOME ($AGENT_HOME) $SIPLG1323MONDESC ($SIPLG1323MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $SIPLG1323MONPATCH oracle.sysman.si.agent.plugin_13.2.3.0.0

	echo -ne "\n\t(7f) OMS CHAINED AGENT HOME ($AGENT_HOME) $BEACONPLG1320DESC ($BEACONPLG1320PATCH)... "
	opatchplugincheck Agent $AGENT_HOME $BEACONPLG1320PATCH oracle.sysman.beacon.agent.plugin_13.2.0.0.0

	echo -ne "\n\t(7g) OMS CHAINED AGENT HOME ($AGENT_HOME) $EXAPLG1321DISCDESC ($EXAPLG1321DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $EXAPLG1321DISCPATCH oracle.sysman.xa.discovery.plugin_13.2.1.0.0

	echo -ne "\n\t(7g) OMS CHAINED AGENT HOME ($AGENT_HOME) $EXAPLG1322DISCDESC ($EXAPLG1322DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $EXAPLG1322DISCPATCH oracle.sysman.xa.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7g) OMS CHAINED AGENT HOME ($AGENT_HOME) $EXAPLG1322MONDESC ($EXAPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $EXAPLG1322MONPATCH oracle.sysman.xa.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7h) OMS CHAINED AGENT HOME ($AGENT_HOME) $EXAPLG1321MONDESC ($EXAPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $EXAPLG1321MONPATCH oracle.sysman.xa.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7i) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWAPPSPLG1321MONDESC ($FMWAPPSPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWAPPSPLG1321MONPATCH oracle.sysman.emfa.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7i) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWAPPSPLG1321DISCDESC ($FMWAPPSPLG1321DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWAPPSPLG1321DISCPATCH oracle.sysman.emfa.discovery.plugin_13.2.1.0.0

	echo -ne "\n\t(7i) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWAPPSPLG1322MONDESC ($FMWAPPSPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWAPPSPLG1322MONPATCH oracle.sysman.emfa.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7i) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWAPPSPLG1322DISCDESC ($FMWPLG1322DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWPLG1322DISCPATCH oracle.sysman.emfa.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7i) OMS CHAINED AGENT HOME ($AGENT_HOME) $FMWAPPSPLG1323MONDESC ($FMWAPPSPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $FMWAPPSPLG1322MONPATCH oracle.sysman.emfa.discovery.plugin_13.2.3.0.0

	echo -ne "\n\t(7j) OMS CHAINED AGENT HOME ($AGENT_HOME) $OVIPLG1321MONDESC ($OVIPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $OVIPLG1321MONPATCH oracle.sysman.vi.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7j) OMS CHAINED AGENT HOME ($AGENT_HOME) $OVIPLG1322MONDESC ($OVIPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $OVIPLG1322MONPATCH oracle.sysman.vi.agent.plugin_13.2.2.0.0

	echo -ne "\n\t(7j) OMS CHAINED AGENT HOME ($AGENT_HOME) $OVIPLG1323MONDESC ($OVIPLG1323MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $OVIPLG1323MONPATCH oracle.sysman.vi.agent.plugin_13.2.3.0.0

	echo -ne "\n\t(7k) OMS CHAINED AGENT HOME ($AGENT_HOME) $OVIPLG1321DISCDESC ($OVIPLG1321DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $OVIPLG1321DISCPATCH oracle.sysman.vi.discovery.plugin_13.2.1.0.0

	echo -ne "\n\t(7k) OMS CHAINED AGENT HOME ($AGENT_HOME) $OVIPLG1322DISCDESC ($OVIPLG1322DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $OVIPLG1322DISCPATCH oracle.sysman.vi.discovery.plugin_13.2.2.0.0

	echo -ne "\n\t(7k) OMS CHAINED AGENT HOME ($AGENT_HOME) $OVIPLG1323DISCDESC ($OVIPLG1323DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $OVIPLG1323DISCPATCH oracle.sysman.vi.discovery.plugin_13.2.3.0.0

	echo -ne "\n\t(7l) OMS CHAINED AGENT HOME ($AGENT_HOME) $VIRTPLG1321MONDESC ($VIRTPLG1321MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $VIRTPLG1321MONPATCH oracle.sysman.vt.agent.plugin_13.2.1.0.0

	echo -ne "\n\t(7l) OMS CHAINED AGENT HOME ($AGENT_HOME) $VIRTPLG1322MONDESC ($VIRTPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $VIRTPLG1322MONPATCH oracle.sysman.vt.agent.plugin_13.2.2.0.0

	echo -ne "\n\t(7l) OMS CHAINED AGENT HOME ($AGENT_HOME) $VIRTPLG1323MONDESC ($VIRTPLG1323MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $VIRTPLG1323MONPATCH oracle.sysman.vt.agent.plugin_13.2.3.0.0

	echo -ne "\n\t(7m) OMS CHAINED AGENT HOME ($AGENT_HOME) $VIRTPLG1321DISCDESC ($VIRTPLG1321DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $VIRTPLG1321DISCPATCH oracle.sysman.vt.discovery.plugin_13.2.1.0.0

	echo -ne "\n\t(7m) OMS CHAINED AGENT HOME ($AGENT_HOME) $VIRTPLG1323DISCDESC ($VIRTPLG1323DISCPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $VIRTPLG1323DISCPATCH oracle.sysman.vt.discovery.plugin_13.2.3.0.0

	echo -ne "\n\t(7n) OMS CHAINED AGENT HOME ($AGENT_HOME) $CSMPLG1322MONDESC ($CSMPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $CSMPLG1322MONPATCH oracle.sysman.csm.agent.plugin_13.2.2.0.0

	echo -ne "\n\t(7n) OMS CHAINED AGENT HOME ($AGENT_HOME) $CSMPLG1323MONDESC ($CSMPLG1323MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $CSMPLG1323MONPATCH oracle.sysman.csm.agent.plugin_13.2.3.0.0

	echo -ne "\n\t(7o) OMS CHAINED AGENT HOME ($AGENT_HOME) $ZDLRAPLG1322MONDESC ($ZDLRAPLG1322MONPATCH)... "
	opatchplugincheck Agent $AGENT_HOME $ZDLRAPLG1322MONPATCH oracle.sysman.am.agent.plugin_13.2.2.0.0
fi

echo
echo

cleantemp

if [[ $FAIL_COUNT -gt "0" ]]; then
	echo "Failed test count: $FAIL_COUNT - Review output"
	echo -e $FAIL_TESTS

	if [[ $EMCLIACCTFAILUREFLAG -gt "0" ]]; then
		echo -e "\n\nIMPORTANT WARNING\n"
		echo "EMCLI failed for some targets due to missing preferred credentials.  You may need to login to EMCLI using a"
		echo "different account, or the account used may need preferred credentials set for some targets."
	fi
else
	echo "All tests succeeded."
fi

echo
echo "Visit https://pardydba.wordpress.com/2016/10/28/securing-oracle-enterprise-manager-13cr2/ for more information."
echo "Download the latest release from https://raw.githubusercontent.com/brianpardy/em13c/master/checksec13R2.sh"
echo "Download the latest beta release from https://raw.githubusercontent.com/brianpardy/em13c/beta/checksec13R2.sh"
echo

exit
