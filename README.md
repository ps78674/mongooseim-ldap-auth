### MongooseIM external LDAP auth plugin
External LDAP auth plugin. Env variables are used for configuring - see example systemd service 'mongooseim.service'.  

The following env variables are mandatory:  
LDAP_SERVER - ldap server address  
LDAP_PORT - ldap port  
LDAP_BASEDN - ldap basedn (dc=example,dc=org')  

The following env variables are optional:  
LDAP_MEMBEROF  
LDAP_SECURECONN - use ldaps or not (true/false)  
LDAP_CHECKPWEXPIRED - check for password expiration via ldap attribute 'krbPasswordExpiration' (true/false)  

Users with expired passwords (krbPasswordExpiration value < time.Now) can't login. Useful for freeIPA users.
