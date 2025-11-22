package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"wireshark/cmd/client"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func chooseInterface() string {
	out := client.Output{}
	resultOut := out.DeviceListOptions()

	if resultOut.Is {
		return ""
	}

	cli := client.Input{}
	prompt := cli.GetOptionOfPrompt("Escolha qual driver será sniffado: ")

	devices, ok := resultOut.Body["devices"].([]pcap.Interface)

	if !ok {
		return ""
	}

	optionDevice := devices[prompt].Name

	return optionDevice
}

func formatTCPFlags(tcp *layers.TCP) string {
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	if len(flags) == 0 {
		return "NONE"
	}
	return strings.Join(flags, ",")
}

func main() {
	var filter string
	if len(os.Args) > 1 {
		filter = os.Args[1]
	}

	device := chooseInterface()
	if device == "" {
		log.Fatal("No valid network interface found")
	}

	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("Error applying BPF filter: %v", err)
		}
	}

	pcapFile, err := os.Create("sniffer.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer pcapFile.Close()

	writer := pcapgo.NewWriter(pcapFile)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	counters := map[string]int{"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
	count := 0

	for packet := range packetSource.Packets() {
		count++
		timestamp := time.Now().Format("15:04:05.000")
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		protocol := "OTHER"
		if packet.Layer(layers.LayerTypeTCP) != nil {
			protocol = "TCP"
			counters["TCP"]++
		} else if packet.Layer(layers.LayerTypeUDP) != nil {
			protocol = "UDP"
			counters["UDP"]++
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
			protocol = "ICMP"
			counters["ICMP"]++
		} else if packet.Layer(layers.LayerTypeARP) != nil {
			protocol = "ARP"
			counters["ARP"]++
		} else {
			counters["OTHER"]++
		}

		fmt.Printf("\n\033[1;36m[%s] Packet #%d (%s)\033[0m\n", timestamp, count, protocol)

		if netLayer := packet.NetworkLayer(); netLayer != nil {
			if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
				ip := ip4.(*layers.IPv4)
				fmt.Printf("  %s → %s | Protocol %s | TTL %d\n", ip.SrcIP, ip.DstIP, ip.Protocol, ip.TTL)
			}
			if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
				ip := ip6.(*layers.IPv6)
				fmt.Printf("  %s → %s | NextHeader %s | HopLimit %d\n", ip.SrcIP, ip.DstIP, ip.NextHeader, ip.HopLimit)
			}
			if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
				a := arp.(*layers.ARP)
				fmt.Printf("  ARP: %v → %v\n", a.SourceProtAddress, a.DstProtAddress)
			}
		}

		if transLayer := packet.TransportLayer(); transLayer != nil {
			if t := packet.Layer(layers.LayerTypeTCP); t != nil {
				tcp := t.(*layers.TCP)
				fmt.Printf("  TCP %d → %d | Flags: %s | Seq %d\n", tcp.SrcPort, tcp.DstPort, formatTCPFlags(tcp), tcp.Seq)
			}
			if u := packet.Layer(layers.LayerTypeUDP); u != nil {
				udp := u.(*layers.UDP)
				fmt.Printf("  UDP %d → %d\n", udp.SrcPort, udp.DstPort)
			}
			if ic := packet.Layer(layers.LayerTypeICMPv4); ic != nil {
				icmp := ic.(*layers.ICMPv4)
				fmt.Printf("  ICMP Type %d Code %d\n", icmp.TypeCode.Type(), icmp.TypeCode.Code())
			}
		}

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			fmt.Printf("  Payload (%d bytes):\n", len(appLayer.Payload()))
			dump := hex.Dump(appLayer.Payload())
			for _, line := range strings.Split(dump, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Println("    " + line)
				}
			}
		}

		fmt.Printf("\033[90mTCP:%d  UDP:%d  ICMP:%d  ARP:%d  OTHER:%d\033[0m\n",
			counters["TCP"], counters["UDP"], counters["ICMP"], counters["ARP"], counters["OTHER"])
		fmt.Println("\033[90m----------------------------------------\033[0m")
	}
}
