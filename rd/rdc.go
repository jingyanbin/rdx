package rd

import (
	"encoding/binary"
	"github.com/jingyanbin/core/basal"
	"github.com/jingyanbin/core/datetime"
	"github.com/jingyanbin/core/log"
	"github.com/jingyanbin/core/xnet"
	"os"
	"strings"
	"time"
)

type Rdc struct {
	config *basal.Json
}

func (m *Rdc) connect(remoteAddr, localAddr string, passwd string, rdAddr string) (*Conn, *Conn, bool) {
	conn2, err := xnet.ConnectTCP(remoteAddr, time.Second*3)
	if err != nil {
		log.Error("connect remote failed: %s, %s", remoteAddr, err.Error())
		return nil, nil, false
	}
	dataRemoteConn := NewConn(conn2)
	if !dataRemoteConn.Send(controlledCmdAuth, []byte(passwd), controlledSeed) {
		log.Error("send remote send failed: %s, %s", remoteAddr, err.Error())
		conn2.Close()
		return nil, nil, false
	}
	conn3, err := xnet.ConnectTCP(localAddr, time.Second*3)
	if err != nil {
		log.Error("connect local failed: %s, %s", localAddr, err.Error())
		conn2.Close()
		return nil, nil, false
	}

	dataLocalConn := NewConn(conn3)
	go CopyConn(dataRemoteConn, dataLocalConn)
	go CopyConn(dataLocalConn, dataRemoteConn)
	log.Info("隧道建立成功, 远程桌面地址: %v", rdAddr)
	return dataRemoteConn, dataLocalConn, true
}

func (m *Rdc) ping() {
	onlineAddr := m.config.Get("online_listen").(string)
	localAddr := m.config.Get("local_listen").(string)
	passwd := m.config.Get("passwd").(string)
	openAuth := m.config.Get("open_auth").(bool)
	conn, err := xnet.ConnectTCP(onlineAddr, time.Second*3)
	if err != nil {
		log.Error("ping connect failed: %s, %s", onlineAddr, err.Error())
		return
	}
	serverConn := NewConn(conn)
	defer serverConn.Close()

	data := make([]byte, 1+len(passwd))
	if openAuth {
		data[0] = 1
	} else {
		data[0] = 0
	}
	copy(data[1:], passwd)
	if !serverConn.Send(onlineCmdAuth, data, onlineSeed) {
		log.Error("ping send failed: %s, %s", onlineAddr)
		return
	}

	cmd, body, success := serverConn.Recv(onlineSeed)
	if !success {
		log.Error("ping recv failed: %s", onlineAddr)
		return
	}
	if cmd != onlineCmdAuthSuccess {
		log.Error("ping recv cmd error: %v", cmd)
		return
	}

	addrs := strings.Split(string(body), ",")
	log.Info("ping resp: %v", addrs)
	if len(addrs[0]) == 0 {
		log.Error("ping resp error: %v", addrs[0])
		return
	}

	remoteConn, localConn, ok := m.connect(addrs[0], localAddr, passwd, addrs[1])
	defer func() {
		log.Info("ping exit")
		if ok {
			remoteConn.Close()
			localConn.Close()
		}
	}()
	pingData := make([]byte, 8)
	pingTicker := time.NewTicker(time.Second * 5)
	defer pingTicker.Stop()
	connectTicker := time.NewTicker(time.Millisecond * 100)
	defer connectTicker.Stop()
	reconnectCount := 0
	reconnectTime := datetime.Unix()
	for {
		select {
		case <-pingTicker.C:
			ns := datetime.UnixNano()
			binary.BigEndian.PutUint64(pingData, uint64(ns))
			if !serverConn.Send(onlineCmdPing, pingData, onlineSeed) {
				log.Error("ping send failed")
				return
			}
			err = serverConn.SetReadDeadline(time.Now().Add(time.Second * 10))
			if err != nil {
				log.Info("ping set read deadline err: %v", err)
				return
			}
			cmd, body, success = serverConn.Recv(onlineSeed)
			if !success {
				log.Error("ping recv failed")
				return
			}
			if cmd == onlineCmdPing {
				st := binary.BigEndian.Uint64(body)
				ms := (uint64(datetime.UnixNano()) - st) / 1e6
				log.Info("ping: %dms", ms)
			} else {
				log.Info("other cmd: %v", cmd)
			}
		case <-connectTicker.C:
			if datetime.Unix()-reconnectTime > 5 {
				reconnectTime = datetime.Unix()
				reconnectCount = 0
				connectTicker.Reset(time.Millisecond * 100)
			}
			if reconnectCount > 2 {
				connectTicker.Reset(time.Second * 5)
				log.Error("重连太频繁,请检查进程是否多开了")
				continue
			}
			if ok {
				if remoteConn.Closed() || localConn.Closed() {
					remoteConn, localConn, ok = m.connect(addrs[0], localAddr, passwd, addrs[1])
					reconnectCount++
				}
			} else {
				remoteConn, localConn, ok = m.connect(addrs[0], localAddr, passwd, addrs[1])
				reconnectCount++
			}

		}
	}
}

func (m *Rdc) Start() bool {
	filename := basal.Path.ProgramDirJoin("rdc.json")
	if f, err := os.Open(filename); err != nil {
		panic(basal.Sprintf("%v, %v", err, filename))
	} else {
		m.config = basal.LoadJson(f)
		f.Close()
	}
	log.Info("users: %v", m.config)
	_, err := basal.SystemCmder.Command("wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1")
	if err != nil {
		log.Error("打开远程桌面服务失败,手动打开")
	} else {
		log.Info("远程桌面服务打开成功")
	}
	loginCmd := `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /t REG_DWORD /v forceguest /d 00000000 /f`
	_, err = basal.SystemCmder.Command(loginCmd)
	if err != nil {
		log.Error("打开远程登录权限失败,请手动打开")
	} else {
		log.Info("打开远程登录权限成功")
	}
	for {
		m.ping()
		time.Sleep(time.Second * 3)
	}
}
