package client

import (
	"fmt"
	"strconv"
	"wireshark/cmd/utils"

	"github.com/google/gopacket/pcap"
)

type Screen interface {
	DeviceListOptions() utils.Error
}

type Output struct{}

func (o *Output) DeviceListOptions() utils.Error {
	// https://github.com/google/gopacket/blob/v1.1.19/pcap/pcap.go#L616
	device, err := pcap.FindAllDevs()
	if err != nil {
		return utils.Error{
			Is: true,
			Body: map[string]any{
				"message": "Error ao capturar DEVICES.",
			},
		}
	}
	logColor := utils.Cor{}

	fmt.Println(logColor.Get().Red + "Seus DRIVERS de Rede:" + logColor.Get().Reset + logColor.Get().Space)

	for i, d := range device {
		fmt.Println("[" + strconv.Itoa(i) + "] " + logColor.Get().Yellow + d.Name + logColor.Get().Reset)
		fmt.Println("--" + logColor.Get().Space)
	}

	return utils.Error{
		Is: false,
		Body: map[string]any{
			"devices": device,
		},
	}
}
