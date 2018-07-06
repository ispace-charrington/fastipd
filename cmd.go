package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ispace-charrington/log"
	"github.com/pkg/errors"
)

var trace bool

func must(msg string, err error) {
	if err == nil {
		if trace {
			fmt.Fprintf(os.Stderr, "ok: %s\n", msg)
		}
		return
	}
	panic(errors.Wrapf(err, "failed to %s", msg))
}

func main() {
	trace = true
	l := log.Default()

	ips := make([]IPv4, 0)

	p, err := NewPool(l.Prefix("pool"), "172.18.99.49/22")
	must("create primary pool", err)

	for {
		ip, err := p.Probe()
		if err != nil {
			break
		}
		ips = append(ips, ip)
		fmt.Printf("p: %T %s, ip: %T %s\n", p, p, ip, ip)
		//time.Sleep(5 * time.Millisecond)
	}
	fmt.Printf("ips: %v\n", ips)
	time.Sleep(31 * time.Second)

}
