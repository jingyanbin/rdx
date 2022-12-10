package rd

import (
	"encoding/binary"
	"fmt"
	"github.com/jingyanbin/core/basal"
	"github.com/jingyanbin/core/datetime"
	"github.com/jingyanbin/core/log"
	"github.com/jingyanbin/core/xnet"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Rda struct {
	config *basal.Json
}

func (m *Rda) Start() bool {
	defer func() {
		log.Info("退出: control + c")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, os.Kill, syscall.SIGTERM)
		select {
		case <-sigCh:
			log.Info("关闭")
		}
	}()

	filename := basal.Path.ProgramDirJoin("rda.json")
	if f, err := os.Open(filename); err != nil {
		log.Error("打开文件失败: %v, %v", err, filename)
		return false
	} else {
		m.config = basal.LoadJson(f)
		f.Close()
	}
	log.Info("config: %v", m.config)
	log.Info("请输入密码:")
	var passwd string
	fmt.Scan(&passwd)

	authAddr := m.config.Get("auth_listen").(string)
	conn, err := xnet.ConnectTCP(authAddr, time.Second*3)
	if err != nil {
		log.Error("连接失败: %v", err)
		return false
	}
	authConn := NewConn(conn)

	data := make([]byte, 8+len(passwd))
	binary.BigEndian.PutUint64(data, uint64(datetime.Unix()))
	copy(data[8:], passwd)
	if _, ok := authConn.Send(controllerCmdAuth, data, controllerSeed); !ok {
		log.Error("授权超时1")
		return false
	}
	err = authConn.SetReadDeadline(time.Now().Add(time.Second * 5))
	if err != nil {
		log.Error("授权超时2: %v", err)
		return false
	}

	cmd, body, _, success := authConn.Recv(controllerSeed)
	if !success {
		log.Error("授权超时3")
		return false
	}
	log.Info("授权返回: %v", string(body))
	if cmd != controllerCmdAuthSuccess {
		return false
	}
	_, err = basal.SystemCmder.Command("mstsc /console")
	if err != nil {
		log.Error("打开远程连接失败,请手动打开")
		return false
	}
	return true
}
