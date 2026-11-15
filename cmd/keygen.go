package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/orgmio/mio/protocol"
)

var commandKeygen = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a server key pair",
	Args:  cobra.NoArgs,
	Run: func(*cobra.Command, []string) {
		if err := Keygen(); err != nil {
			fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandKeygen)
}

// Keygen 生成一对服务端密钥：私钥填进服务端的 [inbounds].private_key，公钥填进客户端的 [outbounds].public_key。
func Keygen() error {
	privateKey, publicKey, err := protocol.GenerateKeyPair()
	if err != nil {
		return err
	}
	fmt.Println("PrivateKey: " + privateKey)
	fmt.Println("PublicKey: " + publicKey)
	return nil
}
