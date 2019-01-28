# joeftp
joeftp - a golang FTP Client Library that implements a FTP client described in RFC 959

A simple library to allow client access to FTP server

see https://www.ietf.org/rfc/rfc959.txt

Currently FTP commands supported
==============================
   PASS <password>
   QUIT
   TYPE <type-code>
   RETR <pathname>
   STOR <pathname>
   DELE <pathname>
   PWD
   LIST
   SITE <string>
   STAT <pathname>]


Sample code

```
package main

import (
	"fmt"
	"github.com/CalypsoSys/joeftp"
)

func main() {
	fmt.Printf("Testing JoeFtp\n")

	ftp := joeftp.JoeFtp{}
	defer ftp.Close()

	ftp.Connect("ftp.cs.brown.edu", 21, true)
	ftp.LogonAnonymous()
	ftp.List()

	ftp.Quit()
}
```
