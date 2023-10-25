package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"encoding/binary"
	"encoding/json"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
)

// Simple source address block / accept structure.
type sourceIP struct {
	IP    string `json:"ip"`
	Allow bool   `json:"allow"`
}

// IP Pairs and whether to block or allow stucture.
type ipPair struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Allow bool   `json:"allow"`
}

// Struct to represent the key with 8 bytes identical to the ipPair map
type BPFAddressPairMapKey struct {
    saddr  uint32
	daddr  uint32
}

// IP data for use with port punching whitelist
type IPData struct {
	IP       string      `json:"ip"`
	Punch	 []PunchData `json:"punch"`
}

type PunchData struct {
	Pass      uint8  `json:"pass"`
	Port      uint16 `json:"port"`
	Protocol  uint8  `json:"protocol"`
	Ratelimit uint32 `json:"rate_limit"`
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
	IP       string `json:"ip"`
	Allow    bool   `json:"allow"` // true == accept default, false == drop default
}

type Configuration struct {
    InterfaceName    string       `json:"interface_name"`
    IPSources        []sourceIP   `json:"ip_source_list"`
    IPPairs          []ipPair     `json:"ip_pair_list"`
    IPData           []IPData     `json:"punch_rules"`
    DefaultBehaviors []IPBehavior `json:"default_behaviors"`
}

func main() {
	// Read the JSON file
    file, configError := os.Open("config.json")
    if configError != nil {
        fmt.Println("Error opening file:", configError)
        return
    }
    defer file.Close()

	decoder := json.NewDecoder(file)
    var config Configuration

    decodingError := decoder.Decode(&config)
    if decodingError != nil {
        fmt.Println("Error decoding JSON:", decodingError)
        return
    }

    fmt.Printf("Interface Name: %s\n", config.InterfaceName)
    fmt.Printf("IP Sources: %v\n", config.IPSources)
    fmt.Printf("IP Pairs: %v\n", config.IPPairs)
    fmt.Printf("Punch Rules: %v\n", config.IPData)
    fmt.Printf("Default Behaviors: %v\n", config.DefaultBehaviors)

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
	err = xdp.Attach(config.InterfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	// Load the rules into maps.
	if err := SourceIPAddresses(config.IPSources, sourcelist); err != nil {
        log.Fatalf("Error blocking IP addresses: %v", err)
    }

	if err := SetAddressesPairs(config.IPPairs, addressPair); err != nil {
		log.Fatalf("Error setting IP address pair list rules: %v", err)
    }

	if err := SetDefaultBehavior(config.DefaultBehaviors, defaultBehavior); err != nil {
		log.Fatalf("Error allowing IP addresses: %v", err)
    }

	if err := SetPunchRules(config.IPData, punch_list); err != nil {
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
				bytesPassed := binary.LittleEndian.Uint64(bytesValue) / 8
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
		log.Println(source.IP, source.Allow)

		// Set the value allow byte
		allowValue := byte(0)
		if source.Allow {
			allowValue = byte(1)
		}

		err := sourcelist.Insert(goebpf.CreateLPMtrieKey(source.IP), allowValue)
		if err != nil {
			return err
		}
	}
	return nil
}

// The function that adds the IP pairs to the addressPair map with the corresponding value for pass or drop.
func SetAddressesPairs(ipPairList []ipPair, addressPair goebpf.Map) error {
	for _, ipPair := range ipPairList {
		log.Println(ipPair.SrcIP, ipPair.DstIP, ipPair.Allow)
		// Create the key struct
		key := BPFAddressPairMapKey {
			saddr: binary.BigEndian.Uint32(net.ParseIP(ipPair.SrcIP).To4()),
			daddr: binary.BigEndian.Uint32(net.ParseIP(ipPair.DstIP).To4()),
		}

		// Convert the key struct to a byte slice thats compatible with the 64 bit map
		keyBytes := make([]byte, 8)
		binary.BigEndian.PutUint32(keyBytes[:4], key.saddr)
		binary.BigEndian.PutUint32(keyBytes[4:], key.daddr)

		// Set the value allow byte
		allowValue := byte(0)
		if ipPair.Allow {
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
		if ipBehavior.Allow {
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