package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/maxmind/mmdbwriter"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type entry struct {
	subnet *net.IPNet
	asn    uint
}

type forSorting []entry

func (a forSorting) Len() int {
	return len(a)
}

func (a forSorting) Swap(x, y int) {
	a[x], a[y] = a[y], a[x]
}

func (a forSorting) Less(x, y int) bool {
	prefix := func(subnet *net.IPNet) net.IP {
		return subnet.IP.Mask(subnet.Mask)
	}
	if bytes.Compare(prefix(a[x].subnet), prefix(a[y].subnet)) < 0 {
		return true
	}
	return false
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("usage: bird2mmdb bird.txt asn.mmdb\n")
		os.Exit(1)
	}
	txtFileName := os.Args[1]
	mmdbFileName := os.Args[2]

	// make writer
	writer, err := mmdbwriter.New(
		mmdbwriter.Options{
			BuildEpoch:   time.Now().Unix(),
			DatabaseType: "CDN77-ASN",
			Description:  map[string]string{"en": "CDN77 BIRD ASN"},
			RecordSize:   24,
			IPVersion:    6,
			Languages:    []string{"en"},
		},
	)
	if err != nil {
		panic(err)
	}

	// gather lines
	lines := []string{}
	txtFile, err := os.Open(txtFileName)
	if err != nil {
		panic(err)
	}
	defer txtFile.Close()
	scanner := bufio.NewScanner(txtFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	// convert CIDR string to subnets, all IPv6
	entries := []entry{}
	for i := 0; i < len(lines); i++ {
		split := strings.Split(lines[i], " ")
		if len(split) != 2 {
			fmt.Printf("line %d has %d fields (expected 2)\n", i, len(split))
		}
		subnet, err := parseCIDR16(split[0])
		if err != nil {
			fmt.Printf("line %d failed to parse: %s (%s)\n", split[0], err)
		}
		asn, err := strconv.ParseUint(split[1], 0, 32)
		if err != nil {
			fmt.Printf("line %d ASN %s failed to parse: %s\n", i, split[1], err)
		}
		entries = append(entries, entry{subnet, uint(asn)})
	}

	// sort by range width such that overlapping subnets are arranged from narrower to wider
	fmt.Println(entries[0])
	sort.Sort(forSorting(entries))
	fmt.Println(entries[0])

	// dump for debugging
	sortedFile, err := os.Create("/tmp/debug.txt")
	defer sortedFile.Close()
	for i := 0; i < len(entries); i++ {
		start := new(big.Int).SetBytes(entries[i].subnet.IP)
		mask := make([]byte, 16)
		copy(mask, entries[i].subnet.Mask)
		for j := 0; j < len(mask); j++ {
			mask[j] = ^mask[j]
		}
		end := new(big.Int).Add(start, new(big.Int).SetBytes(mask))
		sortedFile.WriteString(fmt.Sprintf("%s %s %d\n", start.String(), end.String(), entries[i].asn))
	}

	// populate tree
	/*{
		record := mmdbtype.Map{}
		record["autonomous_system_number"] = mmdbtype.Uint32(asn)
		err = writer.Insert(entry.subnet, entry.record)
		if err != nil {
			panic(err)
		}
	}*/

	mmdbFile, err := os.Create(mmdbFileName)
	if err != nil {
		panic(err)
	}
	defer mmdbFile.Close()

	numBytes, err := writer.WriteTo(mmdbFile)
	if err != nil {
		panic(err)
	}

	fmt.Printf("read %d text lines, written %d bytes\n", len(lines), numBytes)
}

func parseCIDR16(str string) (*net.IPNet, error) {
	ip, subnet, err := net.ParseCIDR(str)
	if err != nil {
		return nil, fmt.Errorf("CIDR failed to parse")
	}
	if len(subnet.IP) == 16 {
		return subnet, nil // already IPv6
	}
	if len(ip) != 16 { // net package behaviour is to parse IPv4 addresses into IPv6 format
		return nil, fmt.Errorf("address parsed to length %d not 16", len(ip))
	}
	mask := net.CIDRMask(96 + prefixLength(subnet), 128) // make a IPv6 mask also
	ip = ip.Mask(mask)
	return &net.IPNet{ip, mask}, nil // now we have an IPv6 subnet
}

func prefixLength(subnet *net.IPNet) int {
	ones, bits := subnet.Mask.Size()
	bits += 0 // unused
	return ones
}
