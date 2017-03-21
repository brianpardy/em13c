# em13c #

This repository contains various utilities for Oracle Enterprise Manager 13c, focused on security. 

## EM13c Security ##

The checksec13R2.sh script implements checks for all of the security configuration I go through for an EM13c R2 environment. It accesses the various configuration files that OEM leaves in place to identify the ports used by, and directories containing, all of your OEM components. 

The provided checks confirm that: 

    * OMS/agent components refuse SSLv2, SSLv3, TLSv1, and TLSv1.1 connections
    * OMS/agent components accept TLSv1.2 connections
    * OMS/agent components refuse LOW and MEDIUM strength cipher suites requested by clients.
    * OMS/agent components accept HIGH strength cipher suites requested by clients.
    * OMS/agent components do not use the default demonstration SSL/TLS certificates distributed with OEM
    * OMS/agent components do not use self-signed SSL/TLS certificates
    * Repository database runs the latest Database Bundle and JavaVM security patches
    * Repository database contains all patches required by EM13c R2
    * Repository database has secure settings for SQL\*Net encryption settings
    * OMS chained agent contains the latest agent bundle patch
    * OMS home contains all the latest recommended, required, and security patches
    * OMS and all agents contain the latest supported Java 7 release
    * OMS and all agents contain the latest required OPatch/OMSPatcher releases
    * All agents contain the latest plugin bundle patches for all installed plugins
    * OMS contains the latest OMS-side plugin bundle patches

All checks accessing remote agents not running on the OMS server require EMCLI integration. I have provided the create\_user\_for\_checksec13R2.sh script in this repository to ease the process of creating an EM13c administrator with the necessary configuration to support EMCLI integration.

If you choose not to use the EMCLI integration, the script will perform all checks that it can on the local server.

These scripts work on Linux x86-64 and users have reported they work on Solaris and AIX. Sorry, Windows users.

## Agent security ## 

The make\_agents\_TLSv1.2.sh and secure\_agent\_ciphersuites.sh scripts provide an automated process to lock down all of your Oracle Management Agents to the most secure TLS protocol (TLSv1.2) and ciphersuite (SSL\_RSA\_WITH\_3DES\_EDE\_CBC\_SHA) available in EM13c R2. 


## SSL/TLS certificates ##
The create\_agent\_wallets.sh and import\_agent\_wallets.sh scripts provide an automated process to generate Oracle wallets for Oracle Management Agents in your OEM landscape. 

### Why bother? ###
Why create this script?  I found the security console in EM13c, though useful, to lack functionality. Though EM13c supplies a patch recommendations tool, I do not find it useful. It reports a need for application of plugin bundle patches on targets that do not have that plugin installed. It reports a need for more than one database PSU, when the most recent database PSU contains all fixes provided in earlier PSUs. I also noticed when working on earlier OEM versions that occasionally installing a patch or re-securing the OMS or various other administrative tasks can reset previously applied security hardening, and I wanted an easy way to repeatedly check the security on my system.


## File Listing ##

* checksec13.sh 
    - This script for EM13c will check your SSL/TLS configuration and patch levels.  Updated infrequently as I no longer have a system available to test with.
* checksec13R2.sh
    - This script for EM13c R2 will check your SSL/TLS configuration and patch levels. Updated with every new patch release, with new features still appearing.
* create\_user\_for\_checksec13R2.sh
    - This script uses EMCLI to create an administrator in EM13c for use by checksec13R2.sh's new features. Optional. You can create your own EMCLI user account or skip the EMCLI integration entirely.
* create\_agent\_wallets.sh
    - This script uses EMCLI and orapki to create Oracle wallets for your EM13c agents.
* import\_agent\_wallets.sh
    - This script uses EMCLI and orapki to import signed certificates to your EM13c agent wallets.
* make\_agents\_TLSv1.2.sh
    - This script uses EMCLI to enable TLSv1.2 and disable earlier TLS protocols for your EM13c agents.
* secure\_agent\_ciphersuites.sh
    - This script uses EMCLI to disable LOW and MEDIUM strength ciphersuites for your EM13c agents.
* sample\_output\_checksec13R2\_with\_EMCLI.txt
    - Sample output from the checksec13R2.sh script when run with EMCLI integration
* sample\_output\_create\_user\_for\_checksec13R2.txt
    - Sample output from the create\_user\_for\_checksec13R2.sh script when run to create a user for EMCLI integration.

## More information ##

See my blog at https://pardydba.wordpress.com/ for more information. Please report any bugs you find or 
