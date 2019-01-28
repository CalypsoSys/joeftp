# joeftp
joeftp - a golang FTP Client Library

A simple library to allow client access to FTP server


Sample code

```
package main

import (
	"fmt"
	"joeftp"
	"regexp"
)

func main() {
	fmt.Printf("Testing JoeFtp\n")

	ftp := joeftp.JoeFtp{}
	defer ftp.Close()

	ftp.Connect("ftp.cs.brown.edu", 21)
	ftp.LogonAnonymous()
	ftp.List()

	ftp.Quit()
}
```
