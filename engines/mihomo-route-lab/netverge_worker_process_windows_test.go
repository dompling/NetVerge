//go:build windows

package tunnel_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Node cannot load Whistle until the parent confirms Job Object assignment.
// Otherwise a fast pfork child can escape before AssignProcessToJobObject.
func nvWhistleCommand(worker string) *exec.Cmd {
	const gate = "process.stdin.once('data', b => { if (b.length !== 1 || b[0] !== 1) process.exit(1); process.stdin.pause(); require(process.argv[1]); }); process.stdin.resume();"
	return exec.Command("node", "-e", gate, "--", worker)
}

// Windows JOBOBJECT_BASIC_ACCOUNTING_INFORMATION layout.
type nvJobAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses uint32
}

func nvWhistleStartContained(cmd *exec.Cmd, stdin io.Writer) (func() error, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil { return nil, err }
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = windows.CloseHandle(job)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA | windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil { return nil, err }
	err = windows.AssignProcessToJobObject(job, process)
	_ = windows.CloseHandle(process)
	if err != nil { return nil, fmt.Errorf("assign worker to job: %w", err) }
	if n, err := stdin.Write([]byte{1}); err != nil || n != 1 { return nil, fmt.Errorf("release worker startup gate: %d %v", n, err) }
	failed = false

	return func() error {
		defer windows.CloseHandle(job)
		if err := windows.TerminateJobObject(job, 1); err != nil { return err }
		deadline := time.Now().Add(5 * time.Second)
		for {
			var counts nvJobAccounting
			if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&counts)), uint32(unsafe.Sizeof(counts)), nil); err != nil { return err }
			if counts.ActiveProcesses == 0 { return nil }
			if time.Now().After(deadline) { return fmt.Errorf("%d worker processes still active", counts.ActiveProcesses) }
			time.Sleep(25 * time.Millisecond)
		}
	}, nil
}

func TestNetVergeWorkerJobCleanup(t *testing.T) {
	script := filepath.Join(t.TempDir(), "worker.js")
	// Both parent and descendant stay alive until cleanup terminates the job.
	const js = "const p=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore',windowsHide:true}); console.log(p.pid); setInterval(()=>{},1000);"
	if err := os.WriteFile(script, []byte(js), 0600); err != nil { t.Fatal(err) }
	cmd := nvWhistleCommand(script)
	stdin, err := cmd.StdinPipe()
	if err != nil { t.Fatal(err) }
	stdout, err := cmd.StdoutPipe()
	if err != nil { t.Fatal(err) }
	stop, err := nvWhistleStartContained(cmd, stdin)
	if err != nil { t.Fatal(err) }
	stopped := false
	t.Cleanup(func() {
		if !stopped { _ = stop() }
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	result := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); result <- line }()
	var pid uint64
	select {
	case line := <-result:
		pid, err = strconv.ParseUint(strings.TrimSpace(line), 10, 32)
		if err != nil { t.Fatal(err) }
	case <-time.After(10 * time.Second):
		t.Fatal("descendant did not start")
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(handle)
	err = stop()
	stopped = true
	if err != nil { t.Fatal(err) }
	if status, err := windows.WaitForSingleObject(handle, 1000); err != nil || status != windows.WAIT_OBJECT_0 { t.Fatalf("worker descendant survived job cleanup: %d %v", status, err) }
	t.Log("PASS: Windows worker Job Object contains and reaps descendants")
}
