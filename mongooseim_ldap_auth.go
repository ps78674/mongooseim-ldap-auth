package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ldap.v3"
)

var logFile string
var ldapAddr string
var ldapPort uint
var baseDN string
var memberOf string

func init() {
	flag.StringVar(&logFile, "logfile", "/var/log/mongooseim/ldap_auth.log", "log file path")
	flag.StringVar(&ldapAddr, "addr", "127.0.0.1", "LDAP server address")
	flag.UintVar(&ldapPort, "port", 389, "LDAP server port")
	flag.StringVar(&baseDN, "basedn", "cn=users,cn=accounts,dc=example,dc=org", "Base DN for user account")
	flag.StringVar(&memberOf, "memberof", "memberof=cn=jabberusers,cn=groups,cn=accounts,dc=example,dc=org", "Jabber users membership")
	flag.Parse()
}

func authenticateUser(username string, password string) bool {
	userDN := "uid=" + username + "," + baseDN
	searchFilter := "(&(uid=" + username + ")(" + memberOf + "))"

	conn, e := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapAddr, ldapPort))
	if e != nil {
		log.Printf("LDAP 'Dial' error - %s", e.Error())
		return false
	}

	e = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if e != nil {
		log.Printf("LDAP 'StartTLS' error - %s", e.Error())
		return false
	}

	e = conn.Bind(userDN, password)
	if e != nil {
		log.Printf("LDAP 'Bind' error - %s", e.Error())
		return false
	}

	searchRequest := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, searchFilter, []string{"krbPasswordExpiration"}, nil)

	res, er := conn.Search(searchRequest)
	if er != nil {
		log.Printf("LDAP 'Search' error - %s", e.Error())
		return false
	} else if len(res.Entries) == 0 {
		log.Printf("User '%s' with membership '%s' is not found.\n", userDN, memberOf)
		return false
	}

	krbPwdExp := res.Entries[0].GetAttributeValue("krbPasswordExpiration")

	if len(krbPwdExp) < 15 {
		log.Println("LDAP attr 'krbPasswordExpiration' length is too short.")
		return false
	}

	year, _ := strconv.Atoi(krbPwdExp[:4])
	month, _ := strconv.Atoi(krbPwdExp[4:6])
	day, _ := strconv.Atoi(krbPwdExp[6:8])
	hour, _ := strconv.Atoi(krbPwdExp[8:10])
	minute, _ := strconv.Atoi(krbPwdExp[10:12])
	second, _ := strconv.Atoi(krbPwdExp[12:14])

	tmExp := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)

	if time.Now().After(tmExp) {
		log.Printf("Password for user '%s' is expired.\n", username)
		return false
	}

	log.Printf("Password for user '%s' is OK.\n", username)
	return true
}

func writeResp(i int) {
	resp := make([]byte, 4)

	binary.BigEndian.PutUint16(resp[0:], uint16(2))
	binary.BigEndian.PutUint16(resp[2:], uint16(i))

	binary.Write(os.Stdout, binary.BigEndian, resp)
}

func main() {
	f, e := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if e != nil {
		log.Fatal(e)
	}

	defer f.Close()
	log.SetOutput(f)

	for {
		reader := bufio.NewReader(os.Stdin)

		p := make([]byte, 2)
		n, e := reader.Read(p)

		if n < 2 {
			continue
		} else if e != nil {
			log.Println(e)
			continue
		}

		size := binary.BigEndian.Uint16(p)
		data := make([]byte, size)

		reader.Read(data)

		op := strings.SplitN(string(data), ":", 4)[0]
		user := strings.SplitN(string(data), ":", 4)[1]
		host := strings.SplitN(string(data), ":", 4)[2]

		log.Printf("operation=%s user=%s host=%s\n", op, user, host)

		if op == "auth" {
			pass := strings.SplitN(string(data), ":", 4)[3]
			result := authenticateUser(user, pass)

			if result {
				writeResp(1)
			} else {
				writeResp(0)
			}

		} else if op == "isuser" {
			writeResp(1)
		} else {
			writeResp(0)
		}
	}
}
