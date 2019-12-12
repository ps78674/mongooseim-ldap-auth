### MongooseIM external LDAP auth plugin
External LDAP auth plugin with checking for krbPasswordExpiration attribute. Users with expired passwords (krbPasswordExpiration value < time.Now) can't login. Useful for freeIPA users.
