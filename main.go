package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	"github.com/cloudfoundry-incubator/bbs/format"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/codegangsta/cli"
	"github.com/kr/pretty"
	"io"
	"os"
)

func main() {
	enc_flags := []cli.Flag{
		cli.StringFlag{
			Name:  "encryptionKey",
			Value: "key1:a secure passphrase",
		},
		cli.StringFlag{
			Name:  "activeKeyLabel",
			Value: "key1",
		},
	}

	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:    "desiredlrpinfo",
			Aliases: []string{"di"},
			Usage:   "decode for DesiredLRPInfo",
			Flags:   enc_flags,
			Action: func(c *cli.Context) {
				var model models.DesiredLRPRunInfo
				print(c, &model)
			},
		},
		{
			Name:    "desiredlrpschedulinginfo",
			Aliases: []string{"dsi"},
			Usage:   "decode for DesiredLRPSchedulingInfo",
			Flags:   enc_flags,
			Action: func(c *cli.Context) {
				var model models.DesiredLRPSchedulingInfo
				print(c, &model)
			},
		},
		{
			Name:    "actuallrp",
			Aliases: []string{"a"},
			Usage:   "decode for ActualLRP",
			Flags:   enc_flags,
			Action: func(c *cli.Context) {
				var model models.ActualLRP
				print(c, &model)
			},
		},
	}
	app.Run(os.Args)
}

type Model interface {
	Unmarshal([]byte) error
}

func print(c *cli.Context, model Model) {
	var err error
	var value []byte
	key := c.String("encryptionKey")
	label := c.String("activeKeyLabel")

	if len(c.Args()) > 0 {
		value = []byte(c.Args()[0])
	} else {
		bio := bufio.NewReader(os.Stdin)
		value, err = bio.ReadBytes(0)
		if err != io.EOF {
			panic(err)
			os.Exit(1)
		}
	}
	err = model.Unmarshal(decrypt([]byte(value), key, label))
	if err != nil {
		fmt.Println(err)
	} else {
		pretty.Print(model)
	}
}

func decrypt(value []byte, key string, label string) []byte {
	args := []string{}
	flagSet := flag.NewFlagSet("", flag.PanicOnError)
	eflags := encryption.AddEncryptionFlags(flagSet)

	args = append(args, "-encryptionKey="+key)
	args = append(args, "-activeKeyLabel="+label)
	flagSet.Parse(args)

	keyManager, err := eflags.Validate()
	encoder := format.NewEncoder(encryption.NewCryptor(keyManager, rand.Reader))
	payload, err := encoder.Decode([]byte(value))

	if err != nil {
		panic(err)
	}

	return payload
}
