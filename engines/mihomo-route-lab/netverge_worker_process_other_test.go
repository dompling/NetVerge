//go:build !windows

package tunnel_test

import (
 "errors"
 "io"
 "os"
 "os/exec"
)

func nvWhistleCommand(worker string) *exec.Cmd { return exec.Command("node", worker) }
func nvWhistleStartContained(cmd *exec.Cmd, _ io.Writer) (func() error,error) {
 if err:=cmd.Start(); err!=nil {return nil,err}
 return func() error {
  err:=cmd.Process.Kill()
  if errors.Is(err,os.ErrProcessDone) {return nil}
  return err
 },nil
}
