package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"encoding/binary"
	"os/signal"

	"github.com/dropbox/goebpf"
)

// IP data for use with port punching whitelist
type IPData struct {
	IP       string
	Punch	 []PunchData
}

type PunchData struct {
	Port     uint16
	Protocol uint8
}

// Struct to represent the key with 8 bytes identical to the punch map
type BPFPunchMapKey struct {
    address  uint32
    port     uint16
    protocol uint8
}

func main() {
	// Specify Interface Name
	interfaceName := "ens3"
	// IP BlockList
	// Add the IPs you want to be blocked
	ipBlockList := []string{
		"45.32.193.17",
	}
	// IP AllowList
	// Add the IPs you want to be allowed
	ipAllowList := []string{
		"47.186.105.124",
	}
	// IP port and protocol punching rules
	// Example data for allowed IP addresses with multiple punchdata
	punchRules := []IPData{
		{
			IP: "127.0.0.1",
			Punch: []PunchData{
				{80, 6}, // Port: 80, Protocol: TCP (6)
				{443, 6}, // Port: 443, Protocol: TCP (6)
			},
		},
		{
			IP: "216.126.237.26",
			Punch: []PunchData{
				{22, 6},
				{80, 6},
				{443, 6},
			},
		},
		// Add more allowed IP data with punchdata as needed
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("bpf/xdp.o")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	blocklist := bpf.GetMapByName("blocklist")
	if blocklist == nil {
		log.Fatalf("eBPF map 'blocklist' not found\n")
	}
	allowlist := bpf.GetMapByName("allowlist")
	if allowlist == nil {
		log.Fatalf("eBPF map 'allowlist' not found\n")
	}
	punch_list := bpf.GetMapByName("punch_list")
	if punch_list == nil {
		log.Fatalf("eBPF map 'punch_list' not found\n")
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	// Load the rules into maps
	if err := BlockIPAddresses(ipBlockList, blocklist); err != nil {
        log.Fatalf("Error blocking IP addresses: %v", err)
    }

	if err := AllowIPAddresses(ipAllowList, allowlist); err != nil {
		log.Fatalf("Error punching rules: %v", err)
    }

	if err := AllowPunchRules(punchRules, punch_list); err != nil {
        log.Fatalf("Error punching rules: %v", err)
    }

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}

// The function that adds the IPs to the blocklist map
func BlockIPAddresses(ipAddreses []string, blocklist goebpf.Map) error {
	for index, ip := range ipAddreses {
		err := blocklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			return err
		}
	}
	return nil
}

// The function that adds the IPs to the allowlist map
func AllowIPAddresses(ipAddreses []string, allowlist goebpf.Map) error {
	for index, ip := range ipAddreses {
		err := allowlist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			return err
		}
	}
	return nil
}

// The function that adds the rules to the allowed BPF_MAP
func AllowPunchRules(punchRules []IPData, allowed goebpf.Map) error {
    for _, data := range punchRules {
		log.Println(data)
        for _, punchData := range data.Punch {
			// Create the key struct
            key := BPFPunchMapKey{
                address:  binary.BigEndian.Uint32(net.ParseIP(data.IP).To4()),
                port:     punchData.Port,
                protocol: punchData.Protocol,
            }

            // Convert the key struct to a byte slice thats compatible with the 64 bit map
            keyBytes := make([]byte, 8)
            binary.BigEndian.PutUint32(keyBytes[:4], key.address)
            binary.BigEndian.PutUint16(keyBytes[4:6], key.port)
            keyBytes[6] = key.protocol
            // No need to set the last byte (padding) since it's automatically initialized to 0s.

			log.Println(key, keyBytes)

            err := allowed.Insert(keyBytes, 0) // Use nil since the value is not needed verifying rules.
            if err != nil {
                return err
            }
        }
    }
    return nil
}