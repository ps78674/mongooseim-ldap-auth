### MongooseIM LDAP Auth plugin
LDAP authentication plugin with password expiration checking (krbPasswordExpiration attribute). Users with expired passwords (krbPasswordExpiration value < time.Now) can't login.
