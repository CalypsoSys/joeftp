// Package joeftp implements a FTP client descrive in RFC 959
//
// see https://www.ietf.org/rfc/rfc959.txt
//
// Currently FTP commands supports
// ==============================
//
//      Yes - USER <SP> <username> <CRLF>
// 	Yes - PASS <SP> <password> <CRLF>
// 	No  - ACCT <SP> <account-information> <CRLF>
// 	No  - CWD  <SP> <pathname> <CRLF>
// 	No  - CDUP <CRLF>
// 	No  - SMNT <SP> <pathname> <CRLF>
// 	Yes - QUIT <CRLF>
// 	No  - REIN <CRLF>
// 	No  - PORT <SP> <host-port> <CRLF>
// 	No  - PASV <CRLF>
// 	Yes - TYPE <SP> <type-code> <CRLF>
// 	No  - STRU <SP> <structure-code> <CRLF>
// 	No  - MODE <SP> <mode-code> <CRLF>
// 	Yes - RETR <SP> <pathname> <CRLF>
// 	Yes - STOR <SP> <pathname> <CRLF>
// 	No  - STOU <CRLF>
// 	No  - APPE <SP> <pathname> <CRLF>
// 	No  - ALLO <SP> <decimal-integer>
// 		[<SP> R <SP> <decimal-integer>] <CRLF>
// 	No  - REST <SP> <marker> <CRLF>
// 	No  - RNFR <SP> <pathname> <CRLF>
// 	No  - RNTO <SP> <pathname> <CRLF>
// 	No  - ABOR <CRLF>
// 	Yes - DELE <SP> <pathname> <CRLF>
// 	No  - RMD  <SP> <pathname> <CRLF>
// 	No  - MKD  <SP> <pathname> <CRLF>
// 	Yes - PWD  <CRLF>
// 	Yes - LIST [<SP> <pathname>] <CRLF>
// 	No  - NLST [<SP> <pathname>] <CRLF>
// 	Yes - SITE <SP> <string> <CRLF>
// 	No  - SYST <CRLF>
// 	Yes - STAT [<SP> <pathname>] <CRLF>
// 	No  - HELP [<SP> <string>] <CRLF>
// 	No  - NOOP <CRLF>
//
// 	Non Passive command
//         ABOR, ALLO, DELE, CWD, CDUP, SMNT, HELP, MODE, NOOP, PASV,
// 		QUIT, SITE, PORT, SYST, STAT, RMD, MKD, PWD, STRU, and TYPE.
//
// 	Commands that require passive
// 		APPE, LIST, NLST, REIN, RETR, STOR, and STOU.
//
package joeftp

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"time"
)

// JoeFtp structure to control access to a FTP server
type JoeFtp struct {
	Host            string
	Port            int
	Timeout         time.Duration
	FTPS            bool
	ExtendedPassive bool
	DebugMode       bool
	conn            net.Conn
}

// Connect creates a TCP connection to a FTP server specifed by host:port
func (ftp *JoeFtp) Connect() (int, string, error) {
	var (
		err  error
		conn net.Conn
	)
	addr := fmt.Sprintf("%s:%d", ftp.Host, ftp.Port)
	if ftp.Timeout > 0 {
		conn, err = net.DialTimeout("tcp", addr, ftp.Timeout)
	} else {
		conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		return 0, "", err
	}
	ftp.conn = conn

	code, msg, err := ftp.readCommand()
	if ftp.FTPS {
		var tlsConn *tls.Conn

		code, msg, err = ftp.SendCommand("AUTH TLS\r\n")
		if err == nil {
			tlsConn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			tlsConn.Handshake()
			ftp.conn = net.Conn(tlsConn)
		}
	}

	return code, msg, err
}

// Close close the extablished tcp connection to the FTP server
func (ftp *JoeFtp) Close() error {
	if ftp.conn != nil {
		return ftp.conn.Close()
	}

	return nil
}

// SendCommand send a command to the FTP server
func (ftp *JoeFtp) SendCommand(command string) (int, string, error) {
	return ftp.sendCommand(command)
}

func (ftp *JoeFtp) sendCommand(command string) (int, string, error) {
	if ftp.Timeout > 0 {
		ftp.conn.SetWriteDeadline(time.Now().Add(ftp.Timeout))
	}
	_, err := ftp.conn.Write([]byte(command))
	if err != nil {
		return 0, "", nil
	}

	return ftp.readCommand()
}

func (ftp *JoeFtp) read(b []byte) (int, error) {
	if ftp.Timeout > 0 {
		err := ftp.conn.SetReadDeadline(time.Now().Add(ftp.Timeout))
		if err != nil {
			return 0, err
		}
	}
	return ftp.conn.Read(b)
}

func (ftp *JoeFtp) readCommand() (int, string, error) {
	rc := make([]byte, 3)
	_, err := ftp.read(rc)
	if err != nil {
		return -1, "", err
	}
	msg := []byte{}
	msg = append(msg, rc...)
	code, err := strconv.Atoi(string(rc))
	if err != nil {
		return -1, string(msg), err
	}

	b := make([]byte, 1)
	_, err = ftp.read(b)
	if err != nil {
		return code, string(msg), err
	}
	msg = append(msg, b...)

	lastLine := true
	if b[0] == '-' {
		lastLine = false
	}
	currentLine := []byte{}
	readMore := true
	var prev byte
	linePos := 4
	for readMore {
		_, err = ftp.read(b)
		if err != nil {
			return code, string(msg), err
		}

		msg = append(msg, b[0])
		if b[0] == '\n' && prev == '\r' {
			if lastLine {
				readMore = false
			} else {
				linePos = 0
				currentLine = []byte{}
			}
		} else {
			linePos++
			if linePos == 4 && b[0] == ' ' {
				testCode, err := strconv.Atoi(string(currentLine))
				if err == nil && testCode == code {
					lastLine = true
				}
			}
			currentLine = append(currentLine, b[0])
		}

		prev = b[0]
	}

	if ftp.DebugMode {
		fmt.Printf("Code: %d\n\n%s\n\nError: %v\n", code, string(msg), err)
	}

	return code, string(msg), err
}

// Logon login to the specified FTP server using the supplied credentials
// used FTP commands: USER and PASS
func (ftp *JoeFtp) Logon(userName string, password string) (int, string, error) {
	if ftp.FTPS {
		code, msg, err := ftp.sendCommand("PBSZ 0\r\n")
		if err != nil {
			return code, msg, err
		}

		code, msg, err = ftp.sendCommand("PROT P\r\n") // encrypt data connection
		if err != nil {
			return code, msg, err
		}
	}

	code, msg, err := ftp.sendCommand(fmt.Sprintf("USER %s\r\n", userName))
	if err != nil {
		return code, msg, err
	}

	return ftp.sendCommand(fmt.Sprintf("PASS %s\r\n", password))
}

// LogonAnonymous login to the specified FTP server using the anonymous user (no password)
// used FTP commands: USER
func (ftp *JoeFtp) LogonAnonymous() (int, string, error) {
	return ftp.sendCommand("USER anonymous\r\n")
}

// Stat This command shall cause a status response to be sent over the control connection in the form of a reply.
// used FTP commands: STAT
func (ftp *JoeFtp) Stat() (int, string, error) {
	return ftp.sendCommand("STAT\r\n")
}

// Site This command is used by the server to provide services
// specific to his system that are essential to file transfer
// but not sufficiently universal to be included as commands in
// the protocol.
//
// used FTP commands: SITE
func (ftp *JoeFtp) Site(parameters string) (int, string, error) {
	return ftp.sendCommand(fmt.Sprintf("SITE %s\r\n", parameters))
}

// Type This command sets the data storage representation
// A = ASCII, E = EBCDIC, I = Binary (image)
// used FTP commands: TYPE
func (ftp *JoeFtp) Type(parameters string) (int, string, error) {
	return ftp.sendCommand(fmt.Sprintf("TYPE %s\r\n", parameters))
}

// List This command retries the current "list" for files to be transfered to the client
// used FTP commands: LIST & PASV
func (ftp *JoeFtp) List() (int, string, []byte, error) {
	return ftp.passive("LIST", nil)
}

// StoreBytes This command shall causes the specified byte stream to be transfered to the FTP server to a file
// used FTP commands: STOR & PASV
func (ftp *JoeFtp) StoreBytes(fileName string, data []byte) (int, string, []byte, error) {
	return ftp.passive(fmt.Sprintf("STOR %s", fileName), data)
}

// StoreFile This command shall causes the specified file to be transfered to the FTP server
// used FTP commands: STOR & PASV
func (ftp *JoeFtp) StoreFile(fileName string, filePath string) (int, string, []byte, error) {
	b, err := ioutil.ReadFile(filePath)
	if err == nil {
		return ftp.StoreBytes(fileName, b)
	}
	return 0, "", nil, err
}

// RetreiveFile This command causes the specifed file to be retrieved from the FTP site
// used FTP commands: RETR & PASV
func (ftp *JoeFtp) RetreiveFile(fileName string) (int, string, []byte, error) {
	return ftp.passive(fmt.Sprintf("RETR %s", fileName), nil)
}

// DeleteFile This command causes the specifed file deleted from the FTP site
// used FTP commands: DELE
func (ftp *JoeFtp) DeleteFile(fileName string) (int, string, error) {
	return ftp.sendCommand(fmt.Sprintf("DELE %s\r\n", fileName))
}

// Quit This command terminated the FTP connection
// used FTP commands: QUIT
func (ftp *JoeFtp) Quit() (int, string, error) {
	return ftp.sendCommand("QUIT\r\n")
}

func (ftp *JoeFtp) passive(command string, dataIn []byte) (int, string, []byte, error) {
	var conn net.Conn

	var passiveCmd, passiveRegex string
	if ftp.ExtendedPassive == true {
		passiveCmd = "EPSV\r\n"
		passiveRegex = `Entering Extended Passive Mode \(\|\|\|(?P<port>\d+)\|\)`
	} else {
		passiveCmd = "PASV\r\n"
		passiveRegex = `Entering Passive Mode \((?P<ip1>\d+),(?P<ip2>\d+),(?P<ip3>\d+),(?P<ip4>\d+),(?P<port1>\d+),(?P<port2>\d+)\)`
	}

	code, msg, err := ftp.sendCommand(passiveCmd)
	if err != nil {
		return code, msg, nil, err
	}
	regPassive := regexp.MustCompile(passiveRegex)
	match := regPassive.FindStringSubmatch(msg)

	paramsMap := make(map[string]string)
	for i, name := range regPassive.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}

	var passiveHost string
	if ftp.ExtendedPassive == true {
		port, err := strconv.Atoi(paramsMap["port"])
		if err != nil {
			return code, msg, nil, err
		}
		passiveHost = fmt.Sprintf("%s:%d", ftp.Host, port)
	} else {
		port1, err := strconv.Atoi(paramsMap["port1"])
		if err != nil {
			return code, msg, nil, err
		}
		port2, err := strconv.Atoi(paramsMap["port2"])
		if err != nil {
			return code, msg, nil, err
		}
		passiveHost = fmt.Sprintf("%s.%s.%s.%s:%d", paramsMap["ip1"], paramsMap["ip2"], paramsMap["ip3"], paramsMap["ip4"], (port1*256)+port2)
	}

	conn, err = net.Dial("tcp", passiveHost)
	if err != nil {
		return code, msg, nil, err
	}
	defer conn.Close()

	code, msg, err = ftp.sendCommand(fmt.Sprintf("%s\r\n", command))
	if err != nil {
		return code, msg, nil, err
	}

	data := []byte{}

	if code == 550 {
		//550 is not expecting anymore data. let's end it now  and send it back.
		//if the cmd was successful & data was coming, code = 125 here
		return code, msg, data, err
	}

	if ftp.FTPS {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		tlsConn.Handshake()
		conn = net.Conn(tlsConn)
	}
	if dataIn == nil {
		b := make([]byte, 1)
		readStream := true
		for readStream {
			if ftp.Timeout > 0 {
				conn.SetReadDeadline(time.Now().Add(ftp.Timeout))
			}
			n, err := conn.Read(b)
			if n == 1 && err == nil {
				data = append(data, b[0])
			} else {
				readStream = false
			}
		}
	} else {
		if ftp.Timeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(ftp.Timeout))
		}
		n, err := conn.Write(dataIn)
		if n == 0 || err != nil {
			return code, msg, data, err
		}
		conn.Close()
	}
	code, msg, err = ftp.readCommand()
	if ftp.DebugMode {
		fmt.Printf("Data: %s", string(data))
	}

	return code, msg, data, err
}
