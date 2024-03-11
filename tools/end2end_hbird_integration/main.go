// Copyright 2018 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/aes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	hbirddp "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/feature"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router/control"
	"github.com/scionproto/scion/tools/integration"
)

var (
	subset      string
	attempts    int
	timeout     = &util.DurWrap{Duration: 10 * time.Second}
	parallelism int
	name        string
	cmd         string
	features    string
)

func getCmd() (string, bool) {
	return cmd, strings.Contains(cmd, "end2end_hbird")
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	addFlags()
	if err := integration.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.HandlePanic()
	defer log.Flush()
	if len(features) != 0 {
		if _, err := feature.ParseDefault(strings.Split(features, ",")); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing features: %s\n", err)
			return 1
		}
	}

	clientArgs := []string{
		"-log.console", "debug",
		"-attempts", strconv.Itoa(attempts),
		"-timeout", timeout.String(),
		"-local", integration.SrcAddrPattern + ":0",
		"-remote", integration.DstAddrPattern + ":" + integration.ServerPortReplace,
	}
	serverArgs := []string{
		"-mode", "server",
		"-local", integration.DstAddrPattern + ":0",
	}
	if len(features) != 0 {
		clientArgs = append(clientArgs, "--features", features)
		serverArgs = append(serverArgs, "--features", features)
	}
	if !*integration.Docker {
		clientArgs = append(clientArgs, "-sciond", integration.Daemon)
		serverArgs = append(serverArgs, "-sciond", integration.Daemon)
	}

	in := integration.NewBinaryIntegration(name, cmd, clientArgs, serverArgs)
	pairs, err := getPairs()
	if err != nil {
		log.Error("Error selecting tests", "err", err)
		return 1
	}
	err = addMockFlyovers(time.Now(), pairs)
	if err != nil {
		log.Error("Error adding mock flyovers", "err", err)
		return 1
	}
	if err := runTests(in, pairs); err != nil {
		log.Error("Error during tests", "err", err)
		return 1
	}
	return 0
}

// addFlags adds the necessary flags.
func addFlags() {
	flag.IntVar(&attempts, "attempts", 1, "Number of attempts per client before giving up.")
	flag.StringVar(&cmd, "cmd", "./bin/end2end_hbird",
		"The end2end binary to run (default: ./bin/end2end_hbird)")
	flag.StringVar(&name, "name", "end2end_hbird_integration",
		"The name of the test that is running (default: end2end_hbird_integration)")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
	flag.StringVar(&subset, "subset", "all", "Subset of pairs to run (all|core#core|"+
		"noncore#localcore|noncore#core|noncore#noncore)")
	flag.IntVar(&parallelism, "parallelism", 1, "How many end2end tests run in parallel.")
	flag.StringVar(&features, "features", "",
		fmt.Sprintf("enable development features (%v)", feature.String(&feature.Default{}, "|")))
}

// runTests runs the end2end hbird tests for all pairs. In case of an error the
// function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		// Make sure that all executed commands can write to the RPC server
		// after shutdown.
		defer time.Sleep(time.Second)

		// Estimating the timeout we should have is hard. CI will abort after 10
		// minutes anyway. Thus this value.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// First run all servers
		type srvResult struct {
			cleaner func()
			err     error
		}
		// Start servers in parallel.
		srvResults := make(chan srvResult)
		for _, dst := range integration.ExtractUniqueDsts(pairs) {
			go func(dst *snet.UDPAddr) {
				defer log.HandlePanic()

				srvCtx, cancel := context.WithCancel(ctx)
				waiter, err := in.StartServer(srvCtx, dst)
				if err != nil {
					log.Error(fmt.Sprintf("Error in server: %s", dst.String()), "err", err)
				}
				cleaner := func() {
					cancel()
					if waiter != nil {
						_ = waiter.Wait()
					}
				}
				srvResults <- srvResult{cleaner: cleaner, err: err}
			}(dst)
		}
		// Wait for all servers being started.
		var errs serrors.List
		for range integration.ExtractUniqueDsts(pairs) {
			res := <-srvResults
			// We need to register a cleanup for all servers.
			// Do not short-cut exit here.
			if res.err != nil {
				errs = append(errs, res.err)
			}
			defer res.cleaner()
		}
		if err := errs.ToError(); err != nil {
			return err
		}

		// Start a done signal listener. This is how the end2end binary
		// communicates with this integration test. This is solely used to print
		// the progress of the test.
		var ctrMtx sync.Mutex
		var ctr int
		doneDir, err := filepath.Abs(filepath.Join(integration.LogDir(), "socks"))
		if err != nil {
			return serrors.WrapStr("determining abs path", err)
		}
		if err := os.MkdirAll(doneDir, os.ModePerm); err != nil {
			return serrors.WrapStr("creating socks directory", err)
		}
		// this is a bit of a hack, socket file names have a max length of 108
		// and inside bazel tests we easily have longer paths, therefore we
		// create a temporary symlink to the directory where we put the socket
		// file.
		tmpDir, err := os.MkdirTemp("", "e2e_hbird_integration")
		if err != nil {
			return serrors.WrapStr("creating temp dir", err)
		}
		if err := os.Remove(tmpDir); err != nil {
			return serrors.WrapStr("deleting temp dir", err)
		}
		if err := os.Symlink(doneDir, tmpDir); err != nil {
			return serrors.WrapStr("symlinking socks dir", err)
		}
		doneDir = tmpDir
		defer os.Remove(doneDir)
		socket, clean, err := integration.ListenDone(doneDir, func(src, dst addr.IA) {
			ctrMtx.Lock()
			defer ctrMtx.Unlock()
			ctr++
			testInfo := fmt.Sprintf("%v -> %v (%v/%v)", src, dst, ctr, len(pairs))
			log.Info(fmt.Sprintf("Test %v: %s", in.Name(), testInfo))
		})
		if err != nil {
			return serrors.WrapStr("creating done listener", err)
		}
		defer clean()

		if *integration.Docker {
			socket = strings.Replace(socket, doneDir, "/share/logs/socks", -1)
		}

		// CI collapses if parallelism is too high.
		semaphore := make(chan struct{}, parallelism)

		// Docker exec comes with a 1 second overhead. We group all the pairs by
		// the clients. And run all pairs for a given client in one execution.
		// Thus, reducing the overhead dramatically.
		groups := integration.GroupBySource(pairs)
		clientResults := make(chan error, len(groups))
		for src, dsts := range groups {
			go func(src *snet.UDPAddr, dsts []*snet.UDPAddr) {
				defer log.HandlePanic()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				// Aggregate all the commands that need to be run.
				cmds := make([]integration.Cmd, 0, len(dsts))
				for _, dst := range dsts {
					cmd, err := clientTemplate(socket).Template(src, dst)
					if err != nil {
						clientResults <- err
						return
					}
					cmds = append(cmds, cmd)
				}
				var tester string
				if *integration.Docker {
					tester = integration.TesterID(src)
				}
				logFile := fmt.Sprintf("%s/client_%s.log",
					logDir(),
					addr.FormatIA(src.IA, addr.WithFileSeparator()),
				)
				err := integration.Run(ctx, integration.RunConfig{
					Commands: cmds,
					LogFile:  logFile,
					Tester:   tester,
				})
				if err != nil {
					err = serrors.WithCtx(err, "file", relFile(logFile))
				}
				clientResults <- err
			}(src, dsts)
		}
		errs = nil
		for range groups {
			err := <-clientResults
			if err != nil {
				errs = append(errs, err)
			}
		}
		return errs.ToError()
	})
}

func clientTemplate(progressSock string) integration.Cmd {
	bin, progress := getCmd()
	cmd := integration.Cmd{
		Binary: bin,
		Args: []string{
			"-log.console", "debug",
			"-attempts", strconv.Itoa(attempts),
			"-timeout", timeout.String(),
			"-local", integration.SrcAddrPattern + ":0",
			"-remote", integration.DstAddrPattern + ":" + integration.ServerPortReplace,
		},
	}
	if len(features) != 0 {
		cmd.Args = append(cmd.Args, "--features", features)
	}
	if progress {
		cmd.Args = append(cmd.Args, "-progress", progressSock)
	}
	if !*integration.Docker {
		cmd.Args = append(cmd.Args, "-sciond", integration.Daemon)
	}
	return cmd
}

// getPairs returns the pairs to test according to the specified subset.
func getPairs() ([]integration.IAPair, error) {
	pairs := integration.IAPairs(integration.DispAddr)
	if subset == "all" {
		return pairs, nil
	}
	parts := strings.Split(subset, "#")
	if len(parts) != 2 {
		return nil, serrors.New("Invalid subset", "subset", subset)
	}
	return filter(parts[0], parts[1], pairs, integration.LoadedASList), nil
}

// filter returns the list of ASes that are part of the desired subset.
func filter(
	src, dst string,
	pairs []integration.IAPair,
	ases *integration.ASList,
) []integration.IAPair {

	var res []integration.IAPair
	s, err1 := addr.ParseIA(src)
	d, err2 := addr.ParseIA(dst)
	if err1 == nil && err2 == nil {
		for _, pair := range pairs {
			if pair.Src.IA.Equal(s) && pair.Dst.IA.Equal(d) {
				res = append(res, pair)
				return res
			}
		}
	}
	for _, pair := range pairs {
		filter := !contains(ases, src != "noncore", pair.Src.IA)
		filter = filter || !contains(ases, dst != "noncore", pair.Dst.IA)
		if dst == "localcore" {
			filter = filter || pair.Src.IA.ISD() != pair.Dst.IA.ISD()
		}
		if !filter {
			res = append(res, pair)
		}
	}
	return res
}

func contains(ases *integration.ASList, core bool, ia addr.IA) bool {
	l := ases.Core
	if !core {
		l = ases.NonCore
	}
	for _, as := range l {
		if ia.Equal(as) {
			return true
		}
	}
	return false
}

// addMockFlyovers creates and stores the necessary flyovers for the given pairs.
// It uses the scion daemon to add the flyovers to the DB.
func addMockFlyovers(now time.Time, pairs []integration.IAPair) error {
	perAS, err := getTopoPerAS(pairs)
	if err != nil {
		return nil
	}

	flyovers, err := createMockFlyovers(perAS, now)
	if err != nil {
		return err
	}

	// Insert each flyover into the DB of each AS. Allow timeout.Duration per AS to do so.
	wg := sync.WaitGroup{}
	wg.Add(len(perAS))
	errCh := make(chan error)
	for ia, c := range perAS {
		ia, c := ia, c
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			ctx, cancelF := context.WithTimeout(context.Background(), timeout.Duration)
			defer cancelF()
			errCh <- insertFlyoversInAS(ctx, ia, c, flyovers)
		}()
	}
	// Collect any possible error and bail on the first non nil one.
	go func() {
		defer log.HandlePanic()
		for errPerAS := range errCh {
			if err != nil {
				err = errPerAS
			}
		}
	}()
	wg.Wait()
	close(errCh)

	if err != nil {
		return serrors.WrapStr("at least one AS returned an error while inserting flyovers", err)
	}
	return nil
}

type topoPerAS struct {
	ASDirName  string
	Interfaces []common.IFIDType
}

func getTopoPerAS(pairs []integration.IAPair) (map[addr.IA]topoPerAS, error) {
	m := make(map[addr.IA]topoPerAS)
	for _, pair := range pairs {
		ia := pair.Src.IA
		if _, ok := m[ia]; ok {
			continue
		}

		// Load their topology.
		path := integration.GenFile(
			filepath.Join(
				addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
				"topology.json",
			),
		)
		topo, err := topology.FromJSONFile(path)
		if err != nil {
			return nil, serrors.WrapStr("loading topology", err, "ia", ia)
		}

		// Set the values for this AS.
		m[ia] = topoPerAS{
			ASDirName: addr.FormatAS(ia.AS(),
				addr.WithDefaultPrefix(), addr.WithFileSeparator()),
			Interfaces: topo.InterfaceIDs(),
		}
	}

	return m, nil
}

func createMockFlyovers(
	perAS map[addr.IA]topoPerAS,
	now time.Time,
) ([]*hummingbird.Flyover, error) {

	// Per IA, insert a flyover with BW units of bandwidth for each interface pair.
	// Note that BW has to be enough for one AS to send a ping to another.
	const BW = uint16(10)
	flyovers := make([]*hummingbird.Flyover, 0)
	for ia, c := range perAS {
		var resIDPerIA uint32 // reservation ID unique per IA
		// Load master key for this ia. It is used to create the mock flyover, by deriving here
		// the correct Ak that the border routers will check.
		masterFile := integration.GenFile(filepath.Join(c.ASDirName, "keys"))
		master0, err := keyconf.LoadMaster(masterFile)
		if err != nil {
			return nil, serrors.WrapStr("could not load master secret for IA", err, "ia", ia)
		}

		// Add the "itself" interface ID to the slice.
		ifaces := append(c.Interfaces, 0)
		// Create a flyover for each possible ingress->egress s.t. ingress <> egress
		inToEgressesMap := ifIDSequenceToMap(ifaces)
		for in, egressInterfaces := range inToEgressesMap {
			for _, eg := range egressInterfaces {
				f := hummingbird.Flyover{
					BaseHop: hummingbird.BaseHop{
						IA:      ia,
						Ingress: uint16(in),
						Egress:  uint16(eg),
					},
					Bw:        BW,
					StartTime: util.TimeToSecs(now),
					// Duration:  60,         // 1 Minute
					// deleteme: change to 1 minute again
					Duration: 300,        // 1 Hour
					ResID:    resIDPerIA, // unique per ia
				}

				key0 := control.DeriveHbirdSecretValue(master0.Key0)
				prf, _ := aes.NewCipher(key0)
				buffer := make([]byte, 16)
				ak := hbirddp.DeriveAuthKey(prf, f.ResID, f.Bw, f.Ingress, f.Egress,
					f.StartTime, f.Duration, buffer)
				copy(f.Ak[:], ak[0:16])

				// Increment the reservation ID per AS to make it unique (per AS).
				resIDPerIA++

				flyovers = append(flyovers, &f)
			}
		}
	}
	return flyovers, nil
}

func insertFlyoversInAS(
	ctx context.Context,
	ia addr.IA,
	config topoPerAS,
	flyovers []*hummingbird.Flyover,
) error {

	daemonAddr, err := integration.GetSCIONDAddress(
		integration.GenFile(integration.DaemonAddressesFile), ia)
	if err != nil {
		return serrors.WrapStr("getting the sciond address", err, "ia", ia)
	}
	conn, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("opening daemon connection", err, "ia", ia)
	}

	err = conn.StoreFlyovers(ctx, flyovers)
	if err != nil {
		return serrors.WrapStr("storing flyovers using daemon", err, "ia", ia)
	}

	err = conn.Close()
	if err != nil {
		return serrors.WrapStr("closing daemon connection", err, "ia", ia)
	}

	return nil
}

// ifIDSequenceToMap takes a slice of interfaces and returns a map where each ingress has
// a list to egress interfaces from the slice.
func ifIDSequenceToMap(ifSeq []common.IFIDType) map[common.IFIDType][]common.IFIDType {

	m := make(map[common.IFIDType][]common.IFIDType, len(ifSeq))
	for _, src := range ifSeq {
		for _, dst := range ifSeq {
			if src == dst {
				continue
			}
			m[src] = append(m[src], dst)
		}
	}
	return m
}

func logDir() string {
	return filepath.Join(integration.LogDir(), name)
}

func relFile(file string) string {
	rel, err := filepath.Rel(filepath.Dir(integration.LogDir()), file)
	if err != nil {
		return file
	}
	return rel
}
