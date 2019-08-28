// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package util

import (
	"fmt"
	"os"
	"path"
	"syscall"
)

//XXX Daemonize has side effect of closing stdout in parent process
// we should double fork
func Daemonize(cmdline []string, workdir string) (pid int, err error) {
	null, err := os.Open("/dev/null")
	if err != nil {
		return -1, err
	}
	f := int(null.Fd())
	os.Stdout.WriteString("test")
	exe := path.Join(workdir, cmdline[0])
	attr := &syscall.ProcAttr{
		Dir:   workdir,
		Files: []uintptr{uintptr(f), uintptr(f), uintptr(f)},
		Sys: &syscall.SysProcAttr{
			//Chroot: workdir,
			Setsid:     true,
			Setpgid:    false,
			Foreground: false,
			//Noctty: true, //XXX this gives bad file descriptor
		},
	}
	fmt.Println("attr ", attr)
	fmt.Println("exe ", exe)
	fmt.Println("cmdline ", cmdline)

	os.Stdin.Close()
	os.Stdout.Close()
	os.Stderr.Close()
	syscall.Dup2(f, int(os.Stdin.Fd()))
	syscall.Dup2(f, int(os.Stdout.Fd()))
	syscall.Dup2(f, int(os.Stderr.Fd()))
	fmt.Println("duped all file descriptors")
	return syscall.ForkExec(exe, cmdline, attr)
}
