package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"encoding/binary"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
)

// Simple source address block / accept structure.
type sourceIP struct {
	saddr  string
	allow  bool
}

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
	Ratelimit uint32
}

// Struct to represent the key with 8 bytes identical to the punch map
type BPFPunchMapKey struct {
    address  uint32
    port     uint16
    protocol uint8
}

// Struct to represent the value identical to the punch map
type BPFPunchMapValue struct {
    pass     uint8
    pps      uint32
    previous uint64 // Set to 0s at init.
}

type IPBehavior struct {
	IP       string
	allow    bool // true == accept default, false == drop default
}

func main() {
	// Specify Interface Name
	interfaceName := "wlo1"
	// IP source list
	// Add the IPs you want to be blocked or allowed universally.
	ipSourceList := []sourceIP{
		{"192.168.0.135", true}, // Allow universally from this address.
		{"45.32.193.177", false}, // Block universally from this address.
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
			IP: "192.168.0.116",
			Punch: []PunchData{
				{1, 22, 6, 0},
				{1, 80, 6, 100},
				{1, 443, 6, 0},
				{1, 0, 1, 0}, // ICMP
			},
		},
		// Add more allowed IP data with punchdata as needed
	}
	// Default allow or drop behavior per IP
	defaultBehaviors := []IPBehavior{
		{
			IP: "216.126.237.26",
			allow: true, // Accept default
		},
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("bpf/xdp.o")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	totalPktStatsMap := bpf.GetMapByName("totalPktStats")
	if totalPktStatsMap == nil {
		log.Fatalf("eBPF map 'totalPktStatsMap' not found\n")
	}
	totalByteStatsMap := bpf.GetMapByName("totalByteStats")
	if totalByteStatsMap == nil {
		log.Fatalf("eBPF map 'totalByteStatsMap' not found\n")
	}
	sourcelist := bpf.GetMapByName("sourcelist")
	if sourcelist == nil {
		log.Fatalf("eBPF map 'sourcelist' not found\n")
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
	if err := SourceIPAddresses(ipSourceList, sourcelist); err != nil {
        log.Fatalf("Error blocking IP addresses: %v", err)
    }

	if err := SetAddressesPairs(ipPairList, addressPair); err != nil {
		log.Fatalf("Error setting IP address pair list rules: %v", err)
    }

	if err := SetDefaultBehavior(defaultBehaviors, defaultBehavior); err != nil {
		log.Fatalf("Error allowing IP addresses: %v", err)
    }

	if err := SetPunchRules(punchRules, punch_list); err != nil {
        log.Fatalf("Error punching rules: %v", err)
    }

	// Execute till interupted
	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Start a Goroutine to print the increasing integer count
	statsCh := make(chan int)
	go printStats(statsCh, totalByteStatsMap, totalPktStatsMap)

	log.Println("XDP Program Loaded successfully into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC
	close(statsCh)
}

func printStats(statsCh chan int, byteStatsMap goebpf.Map, packetStatsMap goebpf.Map) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			/*
			 * Bytes
			*/
			// Perform map lookup and update.
			var bytesKey uint32 = 1
			bytesValue, err := byteStatsMap.Lookup(bytesKey)
			if err == nil {
				bytesPassed := binary.LittleEndian.Uint64(bytesValue)
				kbps := float64(bytesPassed) / 1000
				mbps := float64(bytesPassed) / (1000 * 1000)
				log.Printf("Bytes Passed / Second: %d", bytesPassed)
				log.Printf("Kb/s: %f", kbps)
				log.Printf("Mb/s: %f", mbps)
			} else {
				log.Printf("Error looking up byteStats map: %v", err)
			}
			err = byteStatsMap.Update(bytesKey, uint64(0))
			if err != nil {
				log.Printf("Error inserting value into byteStats map: %v", err)
			}

			/*
			 * Packets
			*/
			// Passed / Sec
			var packetKey uint32 = 1
			packetValue, err := packetStatsMap.Lookup(packetKey)
			if err == nil {
				packetsPassed := binary.LittleEndian.Uint64(packetValue)
				log.Printf("Packets Passed / Second: %d", packetsPassed)
			} else {
				log.Printf("Error looking up packetStats map: %v", err)
			}
			err = packetStatsMap.Update(packetKey, uint64(0))
			if err != nil {
				log.Printf("Error inserting value into packetStats map: %v", err)
			}

			// Dropped / Sec
			var packetDropKey uint32 = 0
			packetDropValue, err := packetStatsMap.Lookup(packetDropKey)
			if err == nil {
				packetsDropped := binary.LittleEndian.Uint64(packetDropValue)
				log.Printf("Packets Dropped / Second: %d", packetsDropped)
			} else {
				log.Printf("Error looking up packetStats map: %v", err)
			}
			err = packetStatsMap.Update(packetDropKey, uint64(0))
			if err != nil {
				log.Printf("Error inserting value into packetStats map: %v", err)
			}

		case <-statsCh:
			return
		}
	}
}

// The function that adds the IPs to the sourcelist map.
func SourceIPAddresses(ipAddreses []sourceIP, sourcelist goebpf.Map) error {
	for _, source := range ipAddreses {
		log.Println(source.saddr, source.allow)

		// Set the value allow byte
		allowValue := byte(0)
		if source.allow {
			allowValue = byte(1)
		}

		err := sourcelist.Insert(goebpf.CreateLPMtrieKey(source.saddr), allowValue)
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
func SetPunchRules(punchRules []IPData, allowed goebpf.Map) error {
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

			value := BPFPunchMapValue {
                pass:     punchData.Pass,
                pps:      punchData.Ratelimit,
                previous: uint64(0),
            }

			// Convert the value struct to a byte slice
            valueBytes := make([]byte, 10)
            valueBytes[0] = value.pass
            binary.BigEndian.PutUint32(valueBytes[1:5], value.pps)
            // No need to put previous because it will be init to 0s.

			// Apply the byte structures to the map.
            err := allowed.Insert(keyBytes, valueBytes) // Use nil since the value is not needed verifying rules.
            if err != nil {
                return err
            }
        }
    }
    return nil
}
/*
// Helper function to read and display statistics from a map
func readAndDisplayStatistics(bpfMap goebpf.Map, mapName string) {
    var keys []uint32
    var values []uint64

    // Iterate over the map to retrieve keys and values
    err := bpfMap.Iterate(nil, func(key, value []byte) int {
        keys = append(keys, binary.BigEndian.Uint32(key))
        values = append(values, binary.LittleEndian.Uint64(value))
        return 0
    })
    if err != nil {
        log.Fatalf("Error iterating over %s map: %v", mapName, err)
    }

    // Display statistics
    fmt.Printf("Statistics from %s map:\n", mapName)
    for i, key := range keys {
        fmt.Printf("Key: %d, Value: %d\n", key, values[i])
    }
    fmt.Println()
}
*/