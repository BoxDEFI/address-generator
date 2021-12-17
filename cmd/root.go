package cmd

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"log"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var waitCount int64
var generateCount int64
var resultChan chan *ecdsa.PrivateKey

func init() {
	RootCommand.Flags().StringVar(&prefix, "prefix", "", "match address prefix")
	RootCommand.Flags().StringVar(&suffix, "suffix", "", "match address suffix")
	RootCommand.Flags().IntVar(&count, "count", 1, "address count")

	resultChan = make(chan *ecdsa.PrivateKey)
}

var prefix string
var suffix string
var count int
var RootCommand = &cobra.Command{
	Use:   "address_generator",
	Short: "evm address generator",
	Run: func(cmd *cobra.Command, args []string) {
		waitCount = int64(count)
		generateCount = 0
		fmt.Println("Start finding address")

		go initSpinner()

		waitGroup := sync.WaitGroup{}
		for i := 0; i < runtime.NumCPU(); i++ {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				generateAddress()
			}()
		}

		waitGroup.Wait()
	},
}

func generateAddress() {
	for {
		if waitCount <= 0 {
			return
		}
		atomic.AddInt64(&generateCount, 1)
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		publicKey := privateKey.Public()
		address := crypto.PubkeyToAddress(*publicKey.(*ecdsa.PublicKey)).Hex()
		if len(prefix) > 0 && !strings.EqualFold(prefix, address[2:2+len(prefix)]) {
			continue
		}
		if len(suffix) > 0 && !strings.EqualFold(suffix, address[len(address)-len(suffix):]) {
			continue
		}

		atomic.AddInt64(&waitCount, -1)
		atomic.StoreInt64(&generateCount, 0)
		resultChan <- privateKey
		break
	}
}

func initSpinner() {
	s := spinner.New(spinner.CharSets[0], 100*time.Millisecond)
	s.Start()
	defer s.Stop()
	tick := time.Tick(1 * time.Second)
	for {
		select {
		case <-tick:
			if waitCount == 0 {
				return
			}
			needTime := math.Pow(16, 20) / math.Pow(16, float64(20-len(prefix)-len(suffix))) / float64(generateCount)
			s.Suffix = fmt.Sprintf("  Approximate ETA for an account Count: %s", time.Duration(int(needTime))*time.Second)
		case privateKey := <-resultChan:
			publicKey := privateKey.Public()
			privateKeyString := hexutil.Encode(crypto.FromECDSA(privateKey))
			address := crypto.PubkeyToAddress(*publicKey.(*ecdsa.PublicKey)).Hex()
			fmt.Printf("\nFound Address: %s ,private key: %s\n", address, privateKeyString)
		}
	}
}

func Execute() {
	if err := RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
