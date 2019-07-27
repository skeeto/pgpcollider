package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/skeeto/optparse-go"
	"github.com/skeeto/passphrase2pgp/openpgp"
)

const (
	// mask selects the bits to be collided.
	mask = (1 << 64) - 1

	// distingish is a mask that determintes the average hash chain length.
	// A chain ends when these bits are all zero. This sets the trade-off
	// between computation time and memory use.
	distinguish = (1 << 17) - 1

	cmdDefault = iota
	cmdClient
	cmdServer
)

// Print the message like fmt.Printf() and then os.Exit(1).
func fatal(format string, args ...interface{}) {
	buf := bytes.NewBufferString("pgpcollider: ")
	fmt.Fprintf(buf, format, args...)
	buf.WriteRune('\n')
	os.Stderr.Write(buf.Bytes())
	os.Exit(1)
}

// expand fills a 32-byte key seed from a 64-bit PRNG seed.
func expand(kseed []byte, seed uint64) {
	for i := 0; i < 4; i++ {
		seed += 0x9e3779b97f4a7c15
		z := seed
		z ^= z >> 30
		z *= 0xbf58476d1ce4e5b9
		z ^= z >> 27
		z *= 0x94d049bb133111eb
		z ^= z >> 31
		binary.LittleEndian.PutUint64(kseed[i*8:], z)
	}
}

// link represents a individual link in a hash chain: a seed and its
// resulting truncated key ID.
type link struct {
	seed    uint64
	truncID uint64
}

// Returns the final truncated key ID of a hash chain starting at the
// given seed, as well as the length of the chain. If not nil, the chain
// itself is recorded into the link slice for inspection.
func computeChain(seed uint64, created int64, record *[]link) (uint64, int) {
	var kseed [32]byte
	var key openpgp.SignKey
	key.SetCreated(created)
	for count := 1; ; count++ {
		expand(kseed[:], seed)
		key.Seed(kseed[:])
		keyID := key.KeyID()
		truncID := binary.BigEndian.Uint64(keyID[12:]) & mask
		if record != nil {
			*record = append(*record, link{seed, truncID})
		}
		seed = truncID
		if truncID&distinguish == 0 {
			return truncID, count
		}
	}
}

// chain represents a complete hash chain: the starting seed, the final
// truncated key ID, and the chain's length.
type chain struct {
	seed    uint64
	truncID uint64
	length  int
}

// Continuously fills the channel with new seeds.
func seeder(seeds chan<- uint64) {
	seed := uint64(time.Now().UnixNano())
	seed ^= seed >> 32
	seed *= 0xd6e8feb86659fd93
	seed ^= seed >> 32
	seed *= 0xd6e8feb86659fd93
	seed ^= seed >> 32
	for {
		seeds <- seed
		seed++
	}
}

// Processes each chain from the channel looking for collisions.
func consumer(chains <-chan chain, config *config) {
	var total int64
	seen := make(map[uint64]uint64)
	mean := newMovingAverage(64)
	start := time.Now()

	for chain := range chains {
		total += int64(chain.length)
		rate := mean.add(float64(total))
		log.Printf("chains %d, keys %d, keys/sec %.0f\n",
			len(seen)+1, total, rate)

		if seed, ok := seen[chain.truncID]; ok {
			// Recreate chains, but record all the links this time.
			var recordA, recordB []link
			computeChain(seed, config.created, &recordA)
			computeChain(chain.seed, config.created, &recordB)

			mapB := make(map[uint64]uint64)
			for _, link := range recordB {
				mapB[link.truncID] = link.seed
			}

			for _, link := range recordA {
				seedB, ok := mapB[link.truncID]
				if !ok {
					continue
				}
				seedA := link.seed

				duration := time.Now().Sub(start)
				log.Printf("duration %s\n", duration)

				var buf bytes.Buffer
				userid := openpgp.UserID{ID: []byte(config.uid)}
				var kseed [32]byte

				// Recreate and self-sign first key
				var keyA openpgp.SignKey
				expand(kseed[:], seedA)
				keyA.Seed(kseed[:])
				keyA.SetCreated(config.created)
				if config.public {
					buf.Write(keyA.PubPacket())
				} else {
					buf.Write(keyA.Packet())
				}
				buf.Write(userid.Packet())
				buf.Write(keyA.Bind(&userid, config.created))
				armor := openpgp.Armor(buf.Bytes())
				if _, err := os.Stdout.Write(armor); err != nil {
					fatal("%s", err)
				}
				buf.Truncate(0)

				// Recreate and self-sign second key
				var keyB openpgp.SignKey
				expand(kseed[:], seedB)
				keyB.Seed(kseed[:])
				keyB.SetCreated(config.created)
				if config.public {
					buf.Write(keyB.PubPacket())
				} else {
					buf.Write(keyB.Packet())
				}
				buf.Write(userid.Packet())
				buf.Write(keyB.Bind(&userid, config.created))
				armor = openpgp.Armor(buf.Bytes())
				if _, err := os.Stdout.Write(armor); err != nil {
					fatal("%s", err)
				}

				log.Printf("key ID %X\n", keyA.KeyID())
				log.Printf("key ID %X\n", keyB.KeyID())

				os.Exit(0)
			}
		} else {
			seen[chain.truncID] = chain.seed
		}
	}
}

// Start a bunch of local chain builders.
func startWorkers(seeds <-chan uint64, chains chan<- chain, created int64) {
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go func() {
			for seed := range seeds {
				truncID, length := computeChain(seed, created, nil)
				chains <- chain{seed, truncID, length}
			}
		}()
	}
}

// Continuously fill a channel with seeds from a connection.
func netSeeder(seeds chan<- uint64, conn net.Conn) {
	var buf [8]byte
	r := bufio.NewReader(conn)
	for {
		if _, err := r.Read(buf[:]); err != nil {
			fatal("%s", err)
		}
		seed := binary.BigEndian.Uint64(buf[:])
		log.Printf("%#016x", seed)
		seeds <- seed
	}
}

// Take chains from the channel and send them over the network.
func netConsumer(chains <-chan chain, conn net.Conn) {
	var buf [20]byte
	for chain := range chains {
		binary.BigEndian.PutUint64(buf[0:], chain.seed)
		binary.BigEndian.PutUint64(buf[8:], chain.truncID)
		binary.BigEndian.PutUint32(buf[16:], uint32(chain.length))
		if _, err := conn.Write(buf[:]); err != nil {
			fatal("%s", err)
		}
	}
}

// Send seeds to remote workers and receive their chains.
func netWorker(seeds <-chan uint64, chains chan<- chain, conn net.Conn) {
	go func() {
		var buf [8]byte
		w := bufio.NewWriter(conn)
		for seed := range seeds {
			binary.BigEndian.PutUint64(buf[:], seed)
			if _, err := w.Write(buf[:]); err != nil {
				log.Println(err)
				return
			}
		}
	}()

	var buf [20]byte
	for {
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			log.Println(err)
			return
		}
		seed := binary.BigEndian.Uint64(buf[0:])
		truncID := binary.BigEndian.Uint64(buf[8:])
		length := int(binary.BigEndian.Uint32(buf[16:]))
		chains <- chain{seed, truncID, length}
	}
}

// Listen for new workers and connect them to the channels.
func workerListen(seeds <-chan uint64, chains chan<- chain,
	addr string, created int64) {

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatal("%s", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("client connected", conn.RemoteAddr())
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(created))
		if _, err := conn.Write(buf[:]); err != nil {
			log.Println(err)
			continue
		}
		go netWorker(seeds, chains, conn)
	}
}

type config struct {
	cmd     int
	addr    string
	help    bool
	public  bool
	created int64
	uid     string
	verbose bool
}

func parse() *config {
	config := config{
		cmd:     cmdDefault,
		created: time.Now().Unix(),
	}

	options := []optparse.Option{
		{"client", 'C', optparse.KindRequired},
		{"server", 'S', optparse.KindRequired},
		{"help", 'h', optparse.KindNone},
		{"public", 'p', optparse.KindNone},
		{"time", 't', optparse.KindRequired},
		{"uid", 'u', optparse.KindRequired},
		{"verbose", 'v', optparse.KindNone},
	}

	results, rest, err := optparse.Parse(options, os.Args)
	if err != nil {
		fatal("%s", err)
	}
	for _, result := range results {
		switch result.Long {
		case "client":
			config.cmd = cmdClient
			config.addr = result.Optarg
		case "server":
			config.cmd = cmdServer
			config.addr = result.Optarg
		case "help":
			usage(os.Stdout)
			os.Exit(0)
		case "public":
			config.public = true
		case "time":
			time, err := strconv.ParseUint(result.Optarg, 10, 32)
			if err != nil {
				fatal("--time (-t): %s", err)
			}
			config.created = int64(time)
		case "uid":
			config.uid = result.Optarg
		case "verbose":
			config.verbose = true
		}
	}

	if len(rest) > 0 {
		fatal("too many arguments")
	}

	return &config
}

func usage(w io.Writer) {
	bw := bufio.NewWriter(w)
	p := "pgpcollider"
	i := "  "
	f := func(s ...interface{}) {
		fmt.Fprintln(bw, s...)
	}
	f("Usage:")
	f(i, p, "[-pv] [-t CREATED] [-u USERID]")
	f(i, p, "-C HOSTNAME [-v]")
	f(i, p, "-S BINDADDR [-pv] [-t CREATED] [-u USERID]")
	f("Commands (distributed computation):")
	f(i, "-C, --server BINDADDR  generate hash chains for a server")
	f(i, "-S, --client HOSTNAME  listen for worker clients")
	f("Options:")
	f(i, "-h, --help             print this help message")
	f(i, "-p, --public           only output the public key")
	f(i, "-t, --time SECONDS     key creation date (unix epoch seconds)")
	f(i, "-u, --uid USERID       user ID for the keys")
	f(i, "-v, --verbose          print progress information")
	bw.Flush()
}

func main() {
	chains := make(chan chain)
	seeds := make(chan uint64)

	config := parse()
	if !config.verbose {
		log.SetOutput(ioutil.Discard)
	}

	switch config.cmd {
	case cmdDefault:
		// Feed unique seeds one at a time to the workers.
		go seeder(seeds)
		// Spin off workers to create chains.
		startWorkers(seeds, chains, config.created)
		consumer(chains, config)
	case cmdClient:
		conn, err := net.Dial("tcp", config.addr)
		if err != nil {
			fatal("%s", err)
		}
		// Get created date
		var buf [4]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			fatal("%s", err)
		}
		created := int64(binary.BigEndian.Uint32(buf[:]))
		// Set up pipeline
		go netSeeder(seeds, conn)
		startWorkers(seeds, chains, created)
		netConsumer(chains, conn)
	case cmdServer:
		// Set up pipeline
		go seeder(seeds)
		go workerListen(seeds, chains, config.addr, config.created)
		consumer(chains, config)
	}
}

type sample struct {
	what float64
	when time.Time
}

type movingAverage struct {
	queue      []sample
	head, tail int
}

func newMovingAverage(n int) *movingAverage {
	return &movingAverage{queue: make([]sample, n)}
}

func (m *movingAverage) add(value float64) float64 {
	head := &m.queue[m.head]
	m.head = (m.head + 1) % len(m.queue)
	if m.head == m.tail {
		m.tail = (m.tail + 1) % len(m.queue)
	}
	tail := &m.queue[m.tail]
	head.what = value
	head.when = time.Now()
	num := head.what - tail.what
	den := head.when.Sub(tail.when).Seconds()
	if den == 0.0 {
		return 0.0
	}
	return num / den
}
