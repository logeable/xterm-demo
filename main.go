package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/text/encoding"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"golang.org/x/crypto/ssh"
)

var (
	addr     string
	username string
	password string
	termEnc encoding.Encoding
	listenAddr string
)

func init() {
	flag.StringVar(&addr, "addr", "localhost:22", "ssh server address")
	flag.StringVar(&username, "u", "root", "username")
	flag.StringVar(&password, "p", "", "password")
	flag.StringVar(&listenAddr, "l", ":9930", "listen address")
	enc := flag.String("enc", "", "term encoding: [gbk]")

	flag.Parse()
	if *enc == "gbk" {
		termEnc = simplifiedchinese.GBK
	}

}

func main() {
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: configHandler(),
	}

	log.Println("listen on:", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func configHandler() http.Handler {
	r := gin.Default()

	r.Static("/xterm", "resources")
	r.GET("/ws", wsHandler)
	return r
}

func wsHandler(ctx *gin.Context) {
	conn, _, handshake, err := ws.UpgradeHTTP(ctx.Request, ctx.Writer)
	log.Println("new ws connection", handshake)
	if err != nil {
		log.Panic("upgrade failed", err)
	}

	go func() {
		defer conn.Close()
		defer func() {
			if r := recover(); r != nil {
				log.Println(r)
			}
		}()

		client, err := sshConnect(addr, username, password)
		if err != nil {
			log.Panic(err)
		}
		defer client.Close()
		log.Println("ssh connected")

		sess, err := client.NewSession()
		if err != nil {
			log.Panicf("ssh new session failed: %s", err)
		}

		sshErr, err := sess.StderrPipe()
		if err != nil {
			log.Panic(err)
		}
		sshOut, err := sess.StdoutPipe()
		if err != nil {
			log.Panic(err)
		}
		sshIn, err := sess.StdinPipe()
		if err != nil {
			log.Panic(err)
		}

		// Set up terminal modes
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}
		// Request pseudo terminal
		if err := sess.RequestPty("xterm", 24, 80, modes); err != nil {
			log.Fatal("request for pseudo terminal failed: ", err)
		}

		err = sess.Shell()
		if err != nil {
			log.Panic(fmt.Errorf("create shell failed: %s", err))
		}

		// pipe ssh server stdout to client
		go func() {
			defer sess.Close()
			buf := make([]byte, 1024)
			for {
				n, err := sshOut.Read(buf)
				if err != nil {
					log.Println("read from ssh stdout failed:", err)
					return
				}

				transformed := buf[:n]
				if termEnc != nil {
					transformed, err = transformToUtf8(buf[:n], termEnc)
					if err != nil {
						log.Println("encoding transform failed:", err)
						return
					}
				}

				data, err := json.Marshal([]string{"stdout", string(transformed)})
				if err != nil {
					log.Println("json marshal failed:", err)
					return
				}

				err = wsutil.WriteServerText(conn, data)
				if err != nil {
					log.Println("write server text failed:", err)
					return
				}
			}
		}()

		// pipe ssh server stderr to client
		go func() {
			defer sess.Close()
			buf := make([]byte, 1024)
			for {
				n, err := sshErr.Read(buf)
				if err != nil {
					log.Println("read from ssh stderr failed:", err)
					return
				}

				transformed := buf[:n]
				if termEnc != nil {
					transformed, err = transformToUtf8(buf[:n], termEnc)
					if err != nil {
						log.Println("encoding transform failed:", err)
						return
					}
				}

				data, err := json.Marshal([]string{"stdout", string(transformed)})
				if err != nil {
					log.Println("json marshal failed:", err)
					return
				}

				err = wsutil.WriteServerText(conn, data)
				if err != nil {
					log.Println("write server text failed:", err)
					return
				}
			}
		}()

		// pipe client to ssh server
		for {
			msg, _, err := wsutil.ReadClientData(conn)
			if err != nil {
				log.Println("read client text failed:", err)
				return
			}

			var data []interface{}
			err = json.Unmarshal(msg, &data)
			if err != nil {
				log.Println("json unmarshal failed:", err)
				log.Println(hex.Dump(msg))
				break
			}

			switch data[0] {
			case "stdin":
				_, err = sshIn.Write([]byte(data[1].(string)))
				if err != nil {
					log.Println("write to ssh stdin failed:", err)
					return
				}
			case "set_size":
				err = sess.WindowChange(int(data[1].(float64)), int(data[2].(float64)))
				if err != nil {
					log.Println("window change failed: ", err)
				}
			default:
				log.Println("read invalid data from client:", data)
				break
			}
		}

	}()
}

func sshConnect(addr, username, password string) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh dial failed: %s", err)
	}
	return client, nil
}

func transformToUtf8(data []byte, enc encoding.Encoding) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(data), enc.NewDecoder())
	bs, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return bs, nil
}
