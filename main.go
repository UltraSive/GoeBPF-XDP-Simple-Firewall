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

// IP Pairs and whether to block or allow stucture.
type ipPair struct {
	saddr  string
	daddr  string
	allow  bool
}

// Struct to represent the key with 8 bytes identical to the ipPair map
type BPFAddressPairMapKey struct {
    saddr  uint32
	daddr  uint32
}

// IP data for use with port punching whitelist
type IPData struct {
	IP       string
	Punch	 []PunchData
}

type PunchData struct {
	Pass      uint8
	Port      uint16
	Protocol  uint8
	Ratelimit uint16
}

// Struct to represent the key with 8 bytes identical to the punch map
type BPFPunchMapKey struct {
    address  uint32
    port     uint16
    protocol uint8
}

type IPBehavior struct {
	IP       string
	allow    bool // true == accept default, false == drop default
}

func main() {
	// Specify Interface Name
	interfaceName := "ens3"
	// IP BlockList
	// Add the IPs you want to be blocked
	ipBlockList := []string{
		"45.32.193.1",
	}
	// IP AllowList
	// Add the IPs you want to be allowed
	ipPairList := []ipPair{
		{"47.186.105.124", "216.126.237.26", true}, // allow
		{"45.32.193.17", "216.126.237.26", false}, // block
	}
	// IP port and protocol punching rules
	// Example data for allowed IP addresses with multiple punchdata
	punchRules := []IPData{
		{
			IP: "127.0.0.1",
			Punch: []PunchData{
				{1, 80, 6, 100}, // Pass: True, Port: 80, Protocol: TCP (6), Ratelimit: 100 PPS
				{0, 443, 6, 0}, // Pass: False, Port: 443, Protocol: TCP (6), Ratelimit: N/A
			},
		},
		{
			IP: "216.126.237.26",
			Punch: []PunchData{
				{1, 22, 6, 0},
				{1, 80, 6, 100},
				{1, 443, 6, 0},
				{1, 123, 1, 0}, // ICMP
			},
		},
		// Add more allowed IP data with punchdata as needed
	}
	// Default allow or drop behavior per IP
	defaultBehaviors := []IPBehavior{
		{
			IP: "216.126.237.26",
			allow: false, // Accept default
		},
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
	addressPair := bpf.GetMapByName("addressPair")
	if addressPair == nil {
		log.Fatalf("eBPF map 'addressPair' not found\n")
	}
	defaultBehavior := bpf.GetMapByName("defaultBehavior")
	if defaultBehavior == nil {
		log.Fatalf("eBPF map 'defaultBehavior' not found\n")
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

	// Load the rules into maps.
	if err := BlockIPAddresses(ipBlockList, blocklist); err != nil {
        log.Fatalf("Error blocking IP addresses: %v", err)
    }

	if err := SetAddressesPairs(ipPairList, addressPair); err != nil {
		log.Fatalf("Error setting IP address pair list rules: %v", err)
    }

	if err := SetDefaultBehavior(defaultBehaviors, defaultBehavior); err != nil {
		log.Fatalf("Error allowing IP addresses: %v", err)
    }

	if err := AllowPunchRules(punchRules, punch_list); err != nil {
        log.Fatalf("Error punching rules: %v", err)
    }

	// Print the content of the maps for troubleshooting.
	log.Println(punch_list)
	log.Println(defaultBehavior)

	// Execute till interupted
	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}

// The function that adds the IPs to the blocklist map.
func BlockIPAddresses(ipAddreses []string, blocklist goebpf.Map) error {
	for index, ip := range ipAddreses {
		log.Println(ip)
		err := blocklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			return err
		}
	}
	return nil
}

// The function that adds the IP pairs to the addressPair map with the corresponding value for pass or drop.
func SetAddressesPairs(ipPairList []ipPair, addressPair goebpf.Map) error {
	for _, ipPair := range ipPairList {
		log.Println(ipPair.saddr, ipPair.daddr, ipPair.allow)
		// Create the key struct
		key := BPFAddressPairMapKey {
			saddr: binary.BigEndian.Uint32(net.ParseIP(ipPair.saddr).To4()),
			daddr: binary.BigEndian.Uint32(net.ParseIP(ipPair.daddr).To4()),
		}

		// Convert the key struct to a byte slice thats compatible with the 64 bit map
		keyBytes := make([]byte, 8)
		binary.BigEndian.PutUint32(keyBytes[:4], key.saddr)
		binary.BigEndian.PutUint32(keyBytes[4:], key.daddr)

		// Set the value allow byte
		allowValue := byte(0)
		if ipPair.allow {
			allowValue = byte(1)
		}

		err := addressPair.Insert(keyBytes, allowValue)
		if err != nil {
			return err
		}
	}
	return nil
}

// The function that adds the default behaviors to the defaultBehavior map.
func SetDefaultBehavior(ipAddreses []IPBehavior, defaultBehaviorMap goebpf.Map) error {
	for _, ipBehavior := range ipAddreses {
		// Set the byte
		allowValue := byte(0)
		if ipBehavior.allow {
			allowValue = byte(1)
		}

		// Insert it into the map.
		log.Println(ipBehavior.IP, allowValue)
		err := defaultBehaviorMap.Insert(goebpf.CreateLPMtrieKey(ipBehavior.IP), allowValue)
		if err != nil {
			return err
		}
	}
	return nil
}

// The function that adds the rules to the allowed BPF_MAP.
func AllowPunchRules(punchRules []IPData, allowed goebpf.Map) error {
    for _, data := range punchRules {
		log.Println(data)
        for _, punchData := range data.Punch {
			// Create the key struct
            key := BPFPunchMapKey {
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

			log.Println(key, keyBytes, byte(punchData.Pass))

            err := allowed.Insert(keyBytes, byte(punchData.Pass)) // Use nil since the value is not needed verifying rules.
            if err != nil {
                return err
            }
        }
    }
    return nil
}