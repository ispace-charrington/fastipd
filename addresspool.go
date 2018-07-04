package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// IPv4 is the raw IP address for a known host
type IPv4 [4]byte

func (a IPv4) netIP() net.IP {
	return a[:]
}
func (a IPv4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
}

// PoolReservation represents a Pool reservation that will expire unless replaced
type PoolReservation struct{}

// Host contains known data about a host in a Pool
type Host struct {
	IPAddress IPv4
	HWAddress net.HardwareAddr
	Hostname  string
	Details   interface{}
}

// Pool represents an IPv4 subnet from which IPv4s can be drawn
type Pool struct {
	mu      sync.RWMutex
	baseIP  IPv4
	net     *net.IPNet
	known   map[IPv4]*Host
	expire  time.Duration
	randsrc *rand.Rand
}

func (p *Pool) String() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return fmt.Sprintf("%s: %d known", p.net, len(p.known))
}

// NewPool will return a Pool corresponding to an IPv4 CIDR (eg "172.18.0.11/16")
func NewPool(cidr string) (*Pool, error) {
	a, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse CIDR notation of %s", cidr)
	}

	if v4 := a.To4(); v4 == nil {
		return nil, fmt.Errorf("cidr %q evaluated to value %v, can't use as ipv4", cidr, a)
	}
	if mbits, _ := n.Mask.Size(); mbits == 0 {
		return nil, fmt.Errorf("cidr %q evaluated to value %v, can't determine mask size", cidr, a)
	}
	p := &Pool{
		// baseIP:  n.IP,
		net:     n,
		known:   make(map[IPv4]*Host),
		expire:  30 * time.Second,
		randsrc: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	copy(p.baseIP[:], n.IP)
	return p, nil
}

func (p *Pool) expireReservation(a IPv4) {
	time.Sleep(p.expire)

	// does this pool still exist?
	if p.known == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// does this map key still exist?
	res := p.known[a]
	if res == nil {
		return
	}

	// does this Host have a details pointer?
	if res.Details == nil {
		return
	}

	switch res.Details.(type) {
	case *PoolReservation:
		// still a reservation, time to delete
		delete(p.known, a)
	default:
		// reservation has been consumed
	}
}

func (p *Pool) randomInRange() (IPv4, error) {
	var nmask, r, k IPv4
	copy(nmask[:], p.net.Mask)
	bits, _ := p.net.Mask.Size()
	maxhosts := (0x1 << uint(32-bits))

	// refuse to randomly allocate from a full pool
	if len(p.known) >= maxhosts {
		return r, fmt.Errorf(
			"Pool contains too many known hosts for %v (hosts: %d)",
			p.net, len(p.known))
	}

	// for now, to prevent runaway in this function, don't allocate more than 50%
	if len(p.known) >= maxhosts/2 {
		return r, fmt.Errorf(
			"Pool is over half full for %v (hosts: %d)",
			p.net, len(p.known))
	}

	for {
		// the documentation says this never fails, so ignore return values
		p.randsrc.Read(k[0:4])

		r[0] = (k[0] & ^nmask[0]) | (p.baseIP[0] & nmask[0])
		r[1] = (k[1] & ^nmask[1]) | (p.baseIP[1] & nmask[1])
		r[2] = (k[2] & ^nmask[2]) | (p.baseIP[2] & nmask[2])
		r[3] = (k[3] & ^nmask[3]) | (p.baseIP[3] & nmask[3])

		if !p.net.Contains(r.netIP()) {
			panic(fmt.Errorf(
				"randomInRange generated an IP %v that isn't contained in %v",
				r.netIP(), p.net))
		}
		if p.known[r] == nil {
			return r, nil
		}
	}
}

// Probe returns an available address from the pool without reserving it
func (p *Pool) Probe() (IPv4, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ip, err := p.randomInRange()
	if err != nil {
		//return ip, errors.Wrapf(err, "Unable to randomly select an IP for Pool %v", p)
		return ip, errors.Wrap(err, "Unable to randomly select an IP for Pool")
	}
	p.known[ip] = &Host{Details: &PoolReservation{}}
	go p.expireReservation(ip)
	return ip, nil
}
