# joeftp
joeftp - a golang FTP and FTPS Client Library that implements a FTP client described in RFC 959 and 4217

A simple library to allow client access to FTP server

see 
* https://www.ietf.org/rfc/rfc959.txt
* https://www.ietf.org/rfc/rfc2428.txt
* https://www.ietf.org/rfc/rfc4217.txt

Current FTP commands supported
   * USER `<username>`
   * PASS `<password>`
   * QUIT
   * TYPE `<type-code>`
   * RETR `<pathname>`
   * STOR `<pathname>`
   * DELE `<pathname>`
   * LIST
   * SITE `<string>`
   * STAT `<pathname>`


Sample code

```
package main

import (
	"fmt"
	"github.com/CalypsoSys/joeftp"
)

func main() {
	fmt.Printf("Testing JoeFtp\n")

	ftp := joeftp.JoeFtp{Host: "ftp.cs.brown.edu", Port: 21, DebugMode: true}
	defer ftp.Close()

	ftp.Connect("ftp.cs.brown.edu", 21, true)
	ftp.LogonAnonymous()
	ftp.List()

	ftp.Quit()
}
```
