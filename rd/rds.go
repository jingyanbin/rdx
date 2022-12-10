package rd

import (
	"encoding/binary"
	"github.com/jingyanbin/core/basal"
	"github.com/jingyanbin/core/datetime"
	"github.com/jingyanbin/core/log"
	"github.com/jingyanbin/core/xnet"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const onlineSeed = 1900
const controlledSeed = 1901
const controllerSeed = 1902

const onlineCmdAuth = 10
const onlineCmdAuthSuccess = 11
const onlineCmdPing = 12

const controlledCmdAuth = 20

const controllerCmdAuth = 30        //控制端认证
const controllerCmdAuthSuccess = 31 //控制端认证成功

var connIndex uint32

type Conn struct {
	passwd string
	id     uint32
	*net.TCPConn
	closed int32
}

func (m *Conn) Closed() bool {
	return atomic.LoadInt32(&m.closed) == 1
}

func (m *Conn) Close() error {
	atomic.CompareAndSwapInt32(&m.closed, 0, 1)
	return m.TCPConn.Close()
}

func (m *Conn) Send(cmd byte, body []byte, seed uint32) (int, bool) {
	bodyLen := len(body)
	total := 6 + bodyLen
	data := make([]byte, total)
	copy(data[6:], body)
	binary.BigEndian.PutUint32(data, uint32(bodyLen))
	data[4] = cmd
	data[5] = xnet.CountBCC(data, 0, 5)
	//log.Info("data1 =============%v, %v", data, string(body))
	xnet.XOREncrypt(seed, data, 6, bodyLen)
	//DefaultNetEncrypt(seed, data, 6, uint32(bodyLen))
	if n, err := xnet.Write(m.TCPConn, data, total); err != nil {
		log.Error("conn send err: %v", err)
		return n, false
	} else {
		return n, true
	}
}

func (m *Conn) Recv(seed uint32) (cmd byte, body []byte, n int, success bool) {
	head := make([]byte, 6)
	n1, err := xnet.Read(m.TCPConn, head, 6)
	if err != nil {
		log.Error("conn read head err: %v", err)
		return 0, nil, n, false
	}
	if bcc := xnet.CountBCC(head, 0, 5); bcc != head[5] {
		log.Error("conn bcc err: %v/%v", bcc, head[5])
		return 0, nil, n, false
	}
	bodyLen := int(binary.BigEndian.Uint32(head))
	cmd = head[4]
	body = make([]byte, bodyLen)
	n2, err := xnet.Read(m.TCPConn, body, bodyLen)
	if err != nil {
		log.Error("conn read body err: %v", err)
		return 0, nil, n1 + n2, false
	}
	xnet.XORDecrypt(seed, body, 0, bodyLen)
	return cmd, body, n1 + n2, true
}

func NewConn(conn *net.TCPConn) *Conn {
	c := &Conn{id: atomic.AddUint32(&connIndex, 1), TCPConn: conn}
	return c
}

func CopyConn(conn1, conn2 *Conn) {
	defer conn1.Close()
	defer conn2.Close()
	_, err := io.Copy(conn1, conn2)
	if err != nil {
		log.Info("CopyConn err: %v", err)
		return
	}
}

type Rds struct {
	config     *basal.Json
	users      *basal.Json
	controlled basal.Map[string, *Conn] //被控者连接 passwd: 连接
	online     basal.Map[string, *Conn] //在线者 passwd: 连接
	//controllers basal.Map[string, *Conn] //控制者
	onlineLis       *net.TCPListener
	authed          basal.Map[string, int64] //ip: 授权结束时间
	netIoStatistics map[string]*NetIOStatistics
}

//func (m *Rds) GetNetIOByPasswd(passwd string) *NetIOStatistics {
//	if v, ok := m.netIoStatistics.Get(passwd); ok {
//		return v
//	}
//	return nil
//}

func (m *Rds) Close() {
	if m.onlineLis != nil {
		m.onlineLis.Close()
	}
	m.online.Range(func(passwd string, conn *Conn) bool {
		conn.Close()
		return true
	})
	m.SaveNetIOStatistics()
}

func (m *Rds) ListenAuth() bool {
	authListen := m.config.Get("auth_listen").(string)
	lis, err := xnet.NewTCPListener(authListen)
	if err != nil {
		log.Error("ListenOneKeyAuth NewTCPListener error: %v", err)
		return false
	}
	defer lis.Close()
	for {
		conn, err := lis.AcceptTCP()
		if err != nil {
			log.Error("ListenOneKeyAuth AcceptTCP error: %v", err)
			return false
		}
		ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
		authConn := NewConn(conn)
		cmd, body, _, success := authConn.Recv(controllerSeed)
		if !success {
			log.Error("授权失败1: %v", ip)
			conn.Close()
			continue
		}
		if cmd != controllerCmdAuth {
			log.Error("授权失败2: %v", ip)
			conn.Close()
			continue
		}
		unix := int64(binary.BigEndian.Uint64(body))
		now := datetime.Unix()
		cha := now - unix
		if cha > 180 || cha < -180 {
			authConn.Send(controllerCmdAuth, []byte("授权失败3"), controllerSeed)
			log.Error("授权失败3: %v", ip)
			conn.Close()
			continue
		}
		if string(body[8:]) != "jyb" {
			authConn.Send(controllerCmdAuth, []byte("授权失败4"), controllerSeed)
			log.Error("授权失败4: %v", ip)
			conn.Close()
			continue
		}
		m.authed.Set(ip, now+300)
		log.Info("授权成功: %v", ip)
		authConn.Send(controllerCmdAuthSuccess, []byte("授权成功, 有效期5分钟"), controllerSeed)
		if m.authed.Len() > 100 {
			var removes []string
			m.authed.Range(func(ip string, unix int64) bool {
				if now-unix > 600 {
					removes = append(removes, ip)
				}
				return true
			})
			for _, authedIp := range removes {
				m.authed.Delete(authedIp, nil)
			}
		}
	}
}

func (m *Rds) ListenOnline() bool {
	onlineListen := m.config.Get("online_listen").(string)
	lis, err := xnet.NewTCPListener(onlineListen)
	if err != nil {
		log.Error("ListenOnline NewTCPListener error: %v", err)
		return false
	}
	m.onlineLis = lis
	defer lis.Close()
	for {
		conn, err := lis.AcceptTCP()
		if err != nil {
			log.Error("ListenOnline AcceptTCP error: %v", err)
			return false
		}
		onlineConn := NewConn(conn)
		go m.handleListenOnline(onlineConn)
	}
}

func (m *Rds) handleListenOnline(conn *Conn) {
	defer func() {
		conn.Close()
		time.Sleep(time.Second * 5)
	}()
	// 接收密码
	err := conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	if err != nil {
		log.Error("handleListenOnline set read deadline err: %v", err)
		return
	}
	log.Info("handleListenOnline connected: %v", conn.RemoteAddr())
	cmd, body, _, success := conn.Recv(onlineSeed)
	if !success {
		log.Error("handleListenOnline recv failed: %v", conn.RemoteAddr())
		return
	}

	if cmd != onlineCmdAuth {
		log.Error("没有认证")
		return
	}
	openAuth := false
	if body[0] == 1 {
		openAuth = true
	}

	passwd := string(body[1:])
	address := m.users.Get(passwd, "listen")
	if address == nil {
		log.Error("handleListenOnline not found passwd: %v", passwd)
		conn.Send(onlineCmdAuth, nil, onlineSeed)
		return
	}
	speed, err := m.users.GetJson(passwd, "speed").ToFloat64()
	if err != nil {
		log.Error("handleListenOnline speed error: %v", err)
		return
	}

	controlledListen := m.config.Get("controlled_listen").(string)
	netIO := m.netIoStatistics[passwd]
	conn.passwd = passwd
	extIp := m.config.Get("ext_ip").(string)
	controlledAddr := extIp + ":" + strings.Split(controlledListen, ":")[1]
	controllerAddr := extIp + ":" + strings.Split(address.(string), ":")[1]
	in, out := netIO.NetIO()
	sendData := basal.Sprintf("%s,%s,%v,%s,%s", controlledAddr, controllerAddr, speed, in, out)
	n, ok := conn.Send(onlineCmdAuthSuccess, []byte(sendData), onlineSeed)
	if !ok {
		log.Error("handleListenOnline send failed: %v", conn.RemoteAddr())
		return
	}
	log.Info("远程桌面地址: %v, %v", passwd, controllerAddr)

	netIO.AddI(n)

	if old := m.online.Set(passwd, conn); old != nil {
		old.Close()
	}

	defer func() {
		m.controlled.Delete(passwd, func(v *Conn) bool {
			v.Close()
			log.Info("删除连接: %v, %v", v.passwd, v.id)
			return true
		})
		m.online.Delete(passwd, func(v *Conn) bool {
			if v.id == conn.id {
				log.Info("删除在线连接: %v, %v", v.passwd, v.id)
				return true
			}
			return false
		})
	}()

	addr := m.users.Get(passwd, "listen").(string)
	lis, err := xnet.NewTCPListener(addr)
	if err != nil {
		log.Error("handleListenOnline NewTCPListener error: %v", err)
		return
	}
	defer lis.Close()
	go func() {
		var passIp string
		var forbidTime int64
		var controllerConn *Conn
		for {
			controller, err := lis.AcceptTCP()
			if err != nil {
				log.Error("handle listen controller AcceptTCP error: %v", err)
				return
			}
			ip := strings.Split(controller.RemoteAddr().String(), ":")[0]

			if openAuth {
				now := datetime.Unix()
				unix, ok := m.authed.Get(ip)
				if !ok {
					log.Error("没有授权: %v, %v", ip, passwd)
					controller.Write([]byte("错误"))
					controller.Close()
					continue
				}
				if now > unix {
					log.Error("授权超时: %v, %v", ip, passwd)
					controller.Write([]byte("错误"))
					controller.Close()
					continue
				}
				log.Info("有权限访问: %v, %v, sec: %v", ip, passwd, unix-now)
			} else {
				log.Info("无需授权")
			}

			if passIp != "" {
				if ip != passIp {
					now := datetime.Unix()
					if now < forbidTime {
						log.Info("10秒内不可访问: %v, %v", ip, forbidTime-now)
						controller.Close()
						continue
					} else {
						log.Info("超过时间限制,可以访问: %v", ip)
					}
				} else {
					log.Info("是之前的连接, 可能是重连: %v", ip)
				}
			}
			passIp = ip
			forbidTime = datetime.Unix() + 10

			log.Info("remote desktop new conn: %v, %v", conn.RemoteAddr(), passwd)
			if controllerConn != nil {
				controllerConn.Write([]byte("错误"))
				controllerConn.Closed()
				time.Sleep(time.Millisecond * 300)
			}
			controllerConn = NewConn(controller)
			controllerConn.passwd = passwd
			controlledConn, ok := m.controlled.Get(passwd)
			if !ok {
				log.Error("not found controlled conn")
				controllerConn.Close()
				continue
			}
			//go CopyConn(controllerConn, controlledConn)
			//go CopyConn(controlledConn, controllerConn)
			go CopyConnIO(controllerConn, controlledConn, netIO.AddO, 32*1024, 0)
			go CopyConnIO(controlledConn, controllerConn, netIO.AddI, 32*1024, 0)
		}
	}()

	for {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * 10))
		if err != nil {
			log.Error("handleListenOnline set read deadline err: %v", err)
			return
		}
		cmd, body, _, success = conn.Recv(onlineSeed)
		if !success {
			log.Error("handleListenOnline recv failed: %v", conn.RemoteAddr())
			return
		}
		if cmd != onlineCmdPing {
			log.Error("收到未知命令: %v, %v", cmd, conn.RemoteAddr())
			continue
		}
		n, ok = conn.Send(cmd, body, onlineSeed)
		if !ok {
			log.Error("handleListenOnline send failed: %v", conn.RemoteAddr())
			return
		}
		netIO.AddI(n)
	}
}

func (m *Rds) ListenControlled() bool {
	controlledListen := m.config.Get("controlled_listen").(string)
	lis, err := xnet.NewTCPListener(controlledListen)
	if err != nil {
		log.Error("ListenControlled NewTCPListener error: %v", err)
		return false
	}
	defer lis.Close()
	for {
		conn, err := lis.AcceptTCP()
		if err != nil {
			log.Error("ListenControlled AcceptTCP error: %v", err)
			return false
		}
		controlledConn := NewConn(conn)
		go m.handleListenControlled(controlledConn)
	}
}

func (m *Rds) handleListenControlled(conn *Conn) {
	// 接收密码
	waiter := basal.Waiter{}
	waiter.Add(1)
	go func() {
		if waiter.Wait(time.Second * 5) {
			log.Info("handleConn auth message: %v", conn.RemoteAddr())
		} else {
			log.Info("handleConn auth message timeout: %v", conn.RemoteAddr())
		}
	}()
	log.Info("handleListenControlled connected: %v", conn.RemoteAddr())
	cmd, body, _, success := conn.Recv(controlledSeed)
	if !success {
		conn.Close()
		log.Error("handleListenControlled recv failed: %v", conn.RemoteAddr())
		return
	}
	waiter.Done()

	if cmd != controlledCmdAuth {
		conn.Close()
		log.Error("handleListenControlled not auth")
		return
	}
	passwd := string(body)
	address := m.users.Get(passwd, "listen")
	if address == nil {
		conn.Close()
		log.Error("handleListenControlled not found passwd: %v", passwd)
		return
	}
	log.Info("隧道连接地址: %v, %v", passwd, conn.RemoteAddr())

	conn.passwd = passwd
	//controlledListen := m.config.Get("controlled_listen").(string)
	//if !conn.Send(1, []byte(controlledListen)) {
	//	conn.Close()
	//	log.Error("handleListenControlled send failed: %v", conn.RemoteAddr())
	//	return
	//}
	if old := m.controlled.Set(passwd, conn); old != nil {
		old.Close()
		log.Info("has old controlled close: %v, %v, %v", old.passwd, old.id, old.RemoteAddr())
	}
	log.Info("handleListenControlled success: %v, %v", conn.RemoteAddr(), conn.passwd)
}

func (m *Rds) LoadConfig() {
	filename := basal.Path.ProgramDirJoin("users.json")
	if f, err := os.Open(filename); err != nil {
		panic(basal.Sprintf("%v, %v", err, filename))
	} else {
		m.users = basal.LoadJson(f)
		f.Close()
	}
	info, _ := m.users.ToString(true)
	log.Info("users: %v", info)
	filename = basal.Path.ProgramDirJoin("rds.json")
	if f, err := os.Open(filename); err != nil {
		panic(basal.Sprintf("%v, %v", err, filename))
	} else {
		m.config = basal.LoadJson(f)
		f.Close()
	}
	info, _ = m.config.ToString(true)
	log.Info("config: %v", info)

	filename = basal.Path.ProgramDirJoin("rds_net_io_statistics.json")
	m.netIoStatistics = make(map[string]*NetIOStatistics)
	err := basal.LoadJsonFileTo(filename, &m.netIoStatistics)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
	}
	users := m.users.Interface().(map[string]interface{})

	for passwd := range users {
		v, ok := m.netIoStatistics[passwd]
		if !ok {

			v = &NetIOStatistics{}
			m.netIoStatistics[passwd] = v
		}
		i, o := v.NetIO()
		log.Info("netIoStatistics: %v, 入流量: %v, 出流量: %v", passwd, i, o)
	}
	m.SaveNetIOStatistics()
}

func (m *Rds) SaveNetIOStatistics() {
	js, err := basal.TryDumpJson(m.netIoStatistics, true)
	if err != nil {
		log.Error("SaveNetIOStatistics dump error: %v", err)
		return
	}
	filename := basal.Path.ProgramDirJoin("rds_net_io_statistics.json")
	f, err := basal.OpenFileB(filename, os.O_WRONLY|os.O_CREATE, 666)
	if err != nil {
		log.Error("SaveNetIOStatistics open error: %v", err)
		return
	}
	defer f.Close()
	_, err = f.WriteString(js)
	if err != nil {
		log.Error("SaveNetIOStatistics write error: %v", err)
		return
	}
}

func (m *Rds) Start() {
	m.LoadConfig()
	log.Info("正在启动...")
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, os.Kill, syscall.SIGTERM)
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for {
			select {
			case <-sigCh:
				log.Info("关闭")
				m.Close()
			case <-ticker.C:
				m.SaveNetIOStatistics()
			}
		}

	}()
	go m.ListenAuth()
	go m.ListenControlled()
	m.ListenOnline()

}
