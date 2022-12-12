package rd

import (
	"github.com/jingyanbin/core/basal"
	"github.com/jingyanbin/core/log"
	"sync/atomic"
	"time"
)

const KB1 float64 = 1024
const MB1 = KB1 * 1024
const GB1 = MB1 * 1024

type NetIOAdd func(n int)

type NetIOStatistics struct {
	IN uint64
	ON uint64
}

func (m *NetIOStatistics) AddI(n int) {
	atomic.AddUint64(&m.IN, uint64(n))
}

func (m *NetIOStatistics) AddO(n int) {
	atomic.AddUint64(&m.ON, uint64(n))
}

func (m *NetIOStatistics) TotalPrice(price float64) float64 {
	total := (float64(m.ON+m.ON) / GB1) * price
	return basal.Round(total, 2)
}

func (m *NetIOStatistics) NetIO() (i, o string) {
	var iStr, oStr string
	iBytes, oBytes := float64(m.IN), float64(m.ON)
	if iBytes > GB1 {
		iStr = basal.Sprintf("%vGB", basal.Round(iBytes/GB1, 3))
	} else if iBytes > MB1 {
		iStr = basal.Sprintf("%vMB", basal.Round(iBytes/MB1, 2))
	} else if iBytes > KB1 {
		iStr = basal.Sprintf("%vKB", basal.Round(iBytes/KB1, 1))
	} else {
		iStr = basal.Sprintf("%vB", basal.Round(iBytes, 0))
	}

	if oBytes > GB1 {
		oStr = basal.Sprintf("%vGB", basal.Round(oBytes/GB1, 3))
	} else if oBytes > MB1 {
		oStr = basal.Sprintf("%vMB", basal.Round(oBytes/MB1, 2))
	} else if oBytes > KB1 {
		oStr = basal.Sprintf("%vKB", basal.Round(oBytes/KB1, 1))
	} else {
		oStr = basal.Sprintf("%vB", basal.Round(oBytes, 0))
	}

	return iStr, oStr
}

func CopyConnIO(dst, src *Conn, srcIO NetIOAdd, size int, interval time.Duration) {
	defer dst.Close()
	defer src.Close()
	data := make([]byte, size)
	src.SetReadBuffer(size)
	for {
		n, err := src.Read(data)
		if err != nil {
			log.Error("src read error: %v, %v", err, src.RemoteAddr())
			return
		}
		srcIO(n)
		_, err = dst.Write(data[:n])
		if err != nil {
			log.Error("dst write error: %v, %v", err, dst.RemoteAddr())
			return
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
}
