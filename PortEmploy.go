//+build linux

package PortEmploy

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)


const (
	PROC_TCP = "/proc/net/tcp"
	PROC_UDP = "/proc/net/udp"
	PROC_TCP6 = "/proc/net/tcp6"
	PROC_UDP6 = "/proc/net/udp6"

)

var STATE = map[string]string {
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type PortEmploy struct {
	Proto		string
	Ip			string
	Port         int64
	User         string
	Name         string
	Pid          string
	Exe          string
}

func getData(t string) []string {
	// Get data from tcp or udp file.

	var proc_t string

	if t == "tcp" {
		proc_t = PROC_TCP
	} else if t == "udp" {
		proc_t = PROC_UDP
	} else if t == "tcp6" {
		proc_t = PROC_TCP6
	} else if t == "udp6" {
		proc_t = PROC_UDP6
	} else {
		fmt.Printf("%s is a invalid type, tcp and udp only!\n", t)
		os.Exit(1)
	}


	data, err := ioutil.ReadFile(proc_t)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1:len(lines) - 1]

}


func hexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return d
}


func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6],  i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		i := []int64{ hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2]) }

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array [] string
	for _, i := range(array) {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

func findPid(inode string) string {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.

	pid := "-"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	re := regexp.MustCompile(inode)
	for _, item := range(d) {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pid = strings.Split(item, "/")[2]
		}
	}
	return pid
}


func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}


func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n) -1]
	return strings.Title(name)
}


func getUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return "Unknown"
	}
	return u.Username
}

func netstat(t string) []PortEmploy {
	var portEmploys []PortEmploy

	data := getData(t)

	for _, line := range(data) {

		// local ip and port
		line_array := removeEmpty(strings.Split(strings.TrimSpace(line), " "))
		ip_port := strings.Split(line_array[1], ":")
		ip := convertIp(ip_port[0])
		port := hexToDec(ip_port[1])
		uid := getUser(line_array[7])
		pid := findPid(line_array[9])
		exe := getProcessExe(pid)
		name := getProcessName(exe)
		// foreign ip and port
		state := STATE[line_array[3]]
		if state != "LISTEN" && (t == "tcp" || t == "tcp6") {
			continue
		}

		p := PortEmploy{
			Proto:t,
			Ip: ip,
			Port: port,
			User:uid,
			Pid: pid,
			Exe: exe,
			Name: name,
		}

		portEmploys = append(portEmploys, p)

	}

	return portEmploys
}


func Tcp() []PortEmploy {
	data := netstat("tcp")
	return data
}


func Udp() []PortEmploy {
	data := netstat("udp")
	return data
}


func Tcp6() []PortEmploy {
	data := netstat("tcp6")
	return data
}


func Udp6() []PortEmploy {
	data := netstat("udp6")
	return data
}

func CheckEmploy(proto,ip string,port int) (bool,PortEmploy) {
	switch proto {
	case "tcp","tcp6" :
		var portEmploy_tcp []PortEmploy
		portEmploy_tcp = append(portEmploy_tcp,Tcp()...)
		portEmploy_tcp = append(portEmploy_tcp,Tcp6()...)
		return checkEmploy(ip,int64(port),portEmploy_tcp)
	case "udp","udp6" :
		var portEmploy_udp []PortEmploy
		portEmploy_udp = append(portEmploy_udp,Udp()...)
		portEmploy_udp = append(portEmploy_udp,Udp6()...)
		return checkEmploy(ip,int64(port),portEmploy_udp)

	}
	return true,PortEmploy{}
}
func checkEmploy(ip string,port int64,portEmploys []PortEmploy) (bool,PortEmploy) {
	for _,protinfo := range portEmploys {
		if protinfo.Port == port {
			if checkaddr(protinfo.Ip,ip) == false {
				return false,protinfo
			}
		}
	}
	return true,PortEmploy{}
}

func checkaddr(ipaddr1,ipaddr2 string) bool {
	ipAddr1 := net.ParseIP(ipaddr1)
	ipAddr2 := net.ParseIP(ipaddr2)

	if ipAddr1.Equal(ipAddr2) {
		return false
	}

	all := net.ParseIP("0.0.0.0")
	if all.Equal(ipAddr1) || all.Equal(ipAddr2) {
		return false
	}

	return true
}

func main(){
	Employ,info := check("tcp","127.0.0.1",22)
	if Employ ==false {
		fmt.Println("检测端口被占用,占用进程信息:",info)
	}
}