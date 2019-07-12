// Copyright (c) Marius Börschig. All rights reserved.
// Licensed under the BSD-3-Clause License.
package util
import (
    "syscall"
    "os"
    "fmt"
)
func Daemonize(cmdline []string, user, workdir string) (pid int, err error) {

    fd, err := os.OpenFile("output.log", os.O_RDWR|os.O_CREATE, 0644)
    if  err != nil {
        return -1, err
    }
    os.Stdin.Close()
    os.Stdout.Close()
    os.Stderr.Close()
    f := int(fd.Fd())
    syscall.Dup2(f, int(os.Stdin.Fd()))
    syscall.Dup2(f, int(os.Stdout.Fd()))
    syscall.Dup2(f, int(os.Stderr.Fd()))
    os.Stdout.WriteString("test")
    fmt.Println("duped all file descriptors")
    attr := &syscall.ProcAttr{
        //Dir: workdir,
        Sys: &syscall.SysProcAttr{
            //Chroot: workdir,
            Setsid: true,
            Setpgid: false,
            Pgid: 0,
            Foreground: false,
            //Noctty: true, //XXX this gives bad file descriptor
        },
    }
    fmt.Println("attr %v", attr)
    //return  syscall.ForkExec(cmdline[0], cmdline[1:], attr)
    return -1, nil
}
