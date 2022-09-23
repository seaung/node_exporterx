package collector

import (
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	MonitorPath []string
	maxFileNum  = kingpin.Flag("max.file.num", "maximum number of monitored file").Default("100").Int()
)

type fileCollector struct {
	fileInfo *prometheus.Desc
	logger   log.Logger
}

func init() {
	registerCollector("file", defaultEnabled, NewFileCollector)
}

// NewFileCollector returns a new Collector exposing ARP stats.
func NewFileCollector(logger log.Logger) (Collector, error) {
	return &fileCollector{
		fileInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "file", "info"),
			"file info",
			[]string{"name", "type", "user", "uid", "group", "gid", "mode", "create_time", "access_time", "modify_time", "md5"}, ConstLabels,
		),
		logger: logger,
	}, nil
}

func (c *fileCollector) Update(ch chan<- prometheus.Metric) error {
	for _, d := range MonitorPath {
		fs, err := ListDir(d)
		if err != nil {
			level.Error(c.logger).Log("get", d, "directory info failed", err)
			continue
		}
		for _, f := range fs {
			if !validUTF8([]byte(f)) {
				continue
			}
			var stat syscall.Stat_t
			err = syscall.Stat(f, &stat)
			if err != nil {
				level.Error(c.logger).Log("get file", f, "info failed", err)
				continue
			}
			fstat, err := os.Stat(f)
			if err != nil {
				level.Error(c.logger).Log("get file", f, "info failed", err)
				continue
			}

			username := strconv.Itoa(int(stat.Uid))
			u, err := user.LookupId(username)
			if err == nil {
				username = u.Username
			}
			group := strconv.Itoa(int(stat.Gid))
			g, err := user.LookupGroupId(group)
			if err == nil {
				group = g.Name
			}

			md5Code := getMd5Code(f)
			ch <- prometheus.MustNewConstMetric(
				c.fileInfo, prometheus.GaugeValue, float64(stat.Size), f,
				"file",
				username,
				strconv.FormatInt(int64(stat.Uid), 10),
				group,
				strconv.FormatInt(int64(stat.Gid), 10),
				fstat.Mode().String(),
				strconv.FormatInt(int64(stat.Ctim.Sec), 10),
				strconv.FormatInt(int64(stat.Atim.Sec), 10),
				strconv.FormatInt(int64(stat.Mtim.Sec), 10),
				md5Code)
		}
	}
	return nil
}

func ListDir(dirPath string) (files []string, err error) {
	fi, err := os.Stat(dirPath)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{dirPath}, nil
	}
	dir, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}
	pathSep := string(os.PathSeparator)
	for _, fi := range dir {
		if fi.IsDir() {
			fs, _ := ListDir(dirPath + pathSep + fi.Name())
			files = append(files, fs...)
		} else {
			files = append(files, dirPath+pathSep+fi.Name())
		}
	}
	if len(files) > *maxFileNum {
		return files[:*maxFileNum], nil
	}
	return files, nil
}

func validUTF8(buf []byte) bool {
	nBytes := 0
	for i := 0; i < len(buf); i++ {
		if nBytes == 0 {
			if (buf[i] & 0x80) != 0 { //与操作之后不为0，说明首位为1
				for (buf[i] & 0x80) != 0 {
					buf[i] <<= 1 //左移一位
					nBytes++     //记录字符共占几个字节
				}

				if nBytes < 2 || nBytes > 6 { //因为UTF8编码单字符最多不超过6个字节
					return false
				}

				nBytes-- //减掉首字节的一个计数
			}
		} else { //处理多字节字符
			if buf[i]&0xc0 != 0x80 { //判断多字节后面的字节是否是10开头
				return false
			}
			nBytes--
		}
	}
	return nBytes == 0
}

func getMd5Code(name string) string {
	md5h := md5.New()
	md5h.Write([]byte(name))
	return hex.EncodeToString(md5h.Sum(nil))
}
