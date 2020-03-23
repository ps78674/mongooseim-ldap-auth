package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ldap.v3"
)

var (
	ldapAddr       string
	ldapPort       string
	baseDN         string
	secureLDAP     bool
	memberOf       string
	checkPWExpired bool
)

const (
	responseOk  = 1
	responseErr = 0
)

func init() {
	ldapAddr = os.Getenv("LDAP_SERVER")
	ldapPort = os.Getenv("LDAP_PORT")
	baseDN = os.Getenv("LDAP_BASEDN")
	memberOf = os.Getenv("LDAP_MEMBEROF")

	var err error
	secureLDAP, err = strconv.ParseBool(os.Getenv("LDAP_SECURECONN"))
	if err != nil {
		os.Stderr.WriteString("cannot parse 'LDAP_SECURECONN', defaulting to false\n")
		secureLDAP = false
	}

	checkPWExpired, err = strconv.ParseBool(os.Getenv("LDAP_CHECKPWEXPIRED"))
	if err != nil {
		os.Stderr.WriteString("cannot parse 'LDAP_CHECKPWEXPIRED', defaulting to false\n")
		checkPWExpired = false
	}

	if len(ldapAddr) == 0 || len(ldapPort) == 0 || len(baseDN) == 0 {
		os.Stderr.WriteString("env vars 'LDAP_SERVER', 'LDAP_PORT', 'LDAP_BASEDN' must be set\n")
		os.Exit(1)
	}
}

func doAuth(username string, password string) bool {
	userDN := fmt.Sprintf("uid=%s,%s", username, baseDN)

	var searchFilter string
	if len(memberOf) > 0 {
		searchFilter = fmt.Sprintf("(&(uid=%s)(%s))", username, memberOf)
	} else {
		searchFilter = fmt.Sprintf("(uid=%s)", username)
	}

	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", ldapAddr, ldapPort))
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("ldap dial error: %s\n", err))
		return false
	}

	if secureLDAP {
		err := conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			os.Stderr.WriteString(fmt.Sprintf("creating tls connection error: %s\n", err))
			return false
		}
	}

	err = conn.Bind(userDN, password)
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("ldap bind error: %s\n", err))
		return false
	}

	if checkPWExpired {
		searchRequest := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, searchFilter, []string{"krbPasswordExpiration"}, nil)
		res, err := conn.Search(searchRequest)
		if err != nil {
			os.Stderr.WriteString(fmt.Sprintf("ldap search error: %s\n", err))
			return false
		} else if len(res.Entries) == 0 {
			os.Stderr.WriteString(fmt.Sprintf("user '%s' not found\n", username))
			return false
		}

		krbPwdExp := res.Entries[0].GetAttributeValue("krbPasswordExpiration")
		if len(krbPwdExp) < 15 {
			os.Stderr.WriteString("length of 'krbPasswordExpiration' is too short\n")
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
			os.Stderr.WriteString(fmt.Sprintf("password for user '%s' is expired\n", username))
			return false
		}
	}

	os.Stderr.WriteString(fmt.Sprintf("password for user '%s' is OK\n", username))
	return true
}

func writeResp(i int) {
	resp := make([]byte, 4)

	binary.BigEndian.PutUint16(resp[0:], uint16(2))
	binary.BigEndian.PutUint16(resp[2:], uint16(i))

	binary.Write(os.Stdout, binary.BigEndian, resp)
}

func main() {
	for {
		reader := bufio.NewReader(os.Stdin)

		p := make([]byte, 2)
		n, err := reader.Read(p)

		if n < 2 {
			continue
		} else if err != nil {
			os.Stderr.WriteString(fmt.Sprintf("error reading stdin: %s\n", err))
			continue
		}

		size := binary.BigEndian.Uint16(p)
		data := make([]byte, size)

		reader.Read(data)

		op := strings.SplitN(string(data), ":", 4)[0]
		user := strings.SplitN(string(data), ":", 4)[1]
		host := strings.SplitN(string(data), ":", 4)[2]

		os.Stderr.WriteString(fmt.Sprintf("operation=%s user=%s host=%s\n", op, user, host))

		if op == "auth" {
			pass := strings.SplitN(string(data), ":", 4)[3]
			result := doAuth(user, pass)

			if result {
				writeResp(responseOk)
			} else {
				writeResp(responseErr)
			}

		} else if op == "isuser" {
			// TODO: actual check for user existence ??
			writeResp(responseOk)
		} else {
			writeResp(responseErr)
		}
	}
}
