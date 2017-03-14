# em13c
Various utilities for Oracle Enterprise Manager 13c
* checksec13.sh 
    - This script for EM13c will check your SSL/TLS configuration and patch levels.  Updated infrequently as I no longer have a system available to test with.
* checksec13R2.sh
    - This script for EM13c R2 will check your SSL/TLS configuration and patch levels. Updated with every new patch release, with new features still appearing.
* create\_user\_for\_checksec13R2.sh
    - This script uses EMCLI to create an administrator in EM13c for use by checksec13R2.sh's new features. Optional.
* create\_agent\_wallets.sh
    - This script uses EMCLI and orapki to create Oracle wallets for your EM13c agents.
* import\_agent\_wallets.sh
    - This script uses EMCLI and orapki to import signed certificates to your EM13c agent wallets.
* make\_agents\_TLSv1.2.sh
    - This script uses EMCLI to enable TLSv1.2 and disable earlier TLS protocols for your EM13c agents.
