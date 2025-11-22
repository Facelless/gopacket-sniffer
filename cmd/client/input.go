package client

import (
	"fmt"
	"strconv"
	"wireshark/cmd/utils"
)

type Prompt interface {
	GetTextOfPrompt(text string) utils.Error
}

type Input struct {
}

func (i *Input) GetOptionOfPrompt(text string) int {
	var option string

	fmt.Printf("%s", text)
	fmt.Scanln(&option)

	num, err := strconv.Atoi(option)
	if err != nil {
		return 0
	}

	return num
}
