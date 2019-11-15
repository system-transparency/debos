package debos

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
)

type ChrootEnterMethod int

const (
	CHROOT_METHOD_NONE   = iota // No chroot in use
	CHROOT_METHOD_NSPAWN        // use nspawn to create the chroot environment
	CHROOT_METHOD_CHROOT        // use chroot to create the chroot environment
	CHROOT_METHOD_DEFAULT       // use the user given choice
)

var DefaultChrootMethod ChrootEnterMethod = CHROOT_METHOD_NSPAWN

type BindMount struct {
	Source string
	Target string
}

type Command struct {
	Architecture string            // Architecture of the chroot, nil if same as host
	Dir          string            // Working dir to run command in
	Chroot       string            // Run in the chroot at path
	ChrootMethod ChrootEnterMethod // Method to enter the chroot

	bindMounts []BindMount // Items to bind mount
	extraEnv   []string  // Extra environment variables to set
}

type commandWrapper struct {
	label  string
	buffer *bytes.Buffer
}

func newCommandWrapper(label string) *commandWrapper {
	b := bytes.Buffer{}
	return &commandWrapper{label, &b}
}

func (w commandWrapper) out(atEOF bool) {
	for {
		s, err := w.buffer.ReadString('\n')
		if err == nil {
			log.Printf("%s | %v", w.label, s)
		} else {
			if len(s) > 0 {
				if atEOF && err == io.EOF {
					log.Printf("%s | %v\n", w.label, s)
				} else {
					w.buffer.WriteString(s)
				}
			}
			break
		}
	}
}

func (w commandWrapper) Write(p []byte) (n int, err error) {
	n, err = w.buffer.Write(p)
	w.out(false)
	return
}

func (w *commandWrapper) flush() {
	w.out(true)
}

func NewChrootCommandForContext(context DebosContext) Command {
	c := Command{Architecture: context.Architecture, Chroot: context.Rootdir, ChrootMethod: CHROOT_METHOD_DEFAULT}

	if context.EnvironVars != nil {
		for k, v := range context.EnvironVars {
			c.AddEnv(fmt.Sprintf("%s=%s", k, v))
		}
	}

	if context.Image != "" {
		path, err := RealPath(context.Image)
		if err == nil {
			c.AddBindMount(path, "")
		} else {
			log.Printf("Failed to get realpath for %s, %v", context.Image, err)
		}
		for _, p := range context.ImagePartitions {
			path, err := RealPath(p.DevicePath)
			if err != nil {
				log.Printf("Failed to get realpath for %s, %v", p.DevicePath, err)
				continue
			}
			c.AddBindMount(path, "")
		}
		c.AddBindMount("/dev/disk", "")
	}

	return c
}

func (cmd *Command) AddEnv(env string) {
	cmd.extraEnv = append(cmd.extraEnv, env)
}

func (cmd *Command) AddEnvKey(key, value string) {
	cmd.extraEnv = append(cmd.extraEnv, fmt.Sprintf("%s=%s", key, value))
}

func (cmd *Command) AddBindMount(source, target string) {
	var mount BindMount

	if target == "" {
		mount.Target = source
	} else {
		mount.Target = target
	}
	mount.Source = source

	cmd.bindMounts = append(cmd.bindMounts, mount)
}

func (cmd *Command) BindMounts() {
	for _, mount := range cmd.bindMounts {
		fmt.Printf("Running mount --bind %s %s\n", mount.Source, fmt.Sprintf("%s/%s", cmd.Chroot, mount.Target))
		os.Mkdir(fmt.Sprintf("%s/%s", cmd.Chroot, mount.Target), 0755)
		exec.Command("mount", "--bind", mount.Source, fmt.Sprintf("%s/%s", cmd.Chroot, mount.Target)).Output()
	}
}

func (cmd *Command) CleanBindMounts() {
	for _, mount := range cmd.bindMounts {
		fmt.Printf("Running umount %s\n", fmt.Sprintf("%s/%s", cmd.Chroot, mount.Target))
		exec.Command("umount", fmt.Sprintf("%s/%s", cmd.Chroot, mount.Target)).Output()
	}
}

func (cmd Command) Run(label string, cmdline ...string) error {
	if cmd.ChrootMethod == CHROOT_METHOD_DEFAULT {
		cmd.ChrootMethod = DefaultChrootMethod
	}

	q := newQemuHelper(cmd)
	q.Setup()

	var options []string
	switch cmd.ChrootMethod {
	case CHROOT_METHOD_NONE:
		options = cmdline
	case CHROOT_METHOD_CHROOT:
		options = append(options, "chroot")
		options = append(options, cmd.Chroot)
		options = append(options, cmdline...)
	case CHROOT_METHOD_NSPAWN:
		options = append(options, "systemd-nspawn", "-q", "-D", cmd.Chroot)
		for _, e := range cmd.extraEnv {
			options = append(options, "--setenv", e)

		}
		for _, b := range cmd.bindMounts {
			options = append(options, "--bind", fmt.Sprintf("%s:%s", b.Source, b.Target))

		}
		options = append(options, cmdline...)
	}

	exe := exec.Command(options[0], options[1:]...)
	w := newCommandWrapper(label)

	exe.Stdin = nil
	exe.Stdout = w
	exe.Stderr = w

	if len(cmd.extraEnv) > 0 && cmd.ChrootMethod != CHROOT_METHOD_NSPAWN {
		exe.Env = append(os.Environ(), cmd.extraEnv...)
	}

	// Disable services start/stop for commands running in chroot
	if cmd.ChrootMethod != CHROOT_METHOD_NONE {
		services := ServiceHelper{cmd.Chroot}
		services.Deny()
		defer services.Allow()

	}

	if cmd.ChrootMethod == CHROOT_METHOD_CHROOT {
		cmd.BindMounts()
	}

	err := exe.Run()
	w.flush()
	q.Cleanup()

	if cmd.ChrootMethod == CHROOT_METHOD_CHROOT {
		cmd.CleanBindMounts()
	}

	return err
}

type qemuHelper struct {
	qemusrc    string
	qemutarget string
}

func newQemuHelper(c Command) qemuHelper {
	q := qemuHelper{}

	if c.Chroot == "" || c.Architecture == "" {
		return q
	}

	switch c.Architecture {
	case "armhf", "armel", "arm":
		q.qemusrc = "/usr/bin/qemu-arm-static"
	case "arm64":
		q.qemusrc = "/usr/bin/qemu-aarch64-static"
	case "mips":
		q.qemusrc = "/usr/bin/qemu-mips-static"
	case "mipsel":
		q.qemusrc = "/usr/bin/qemu-mipsel-static"
	case "mips64el":
		q.qemusrc = "/usr/bin/qemu-mips64el-static"
	case "riscv64":
		q.qemusrc = "/usr/bin/qemu-riscv64-static"
	case "amd64", "i386":
		/* Dummy, no qemu */
	default:
		log.Panicf("Don't know qemu for Architecture %s", c.Architecture)
	}

	if q.qemusrc != "" {
		q.qemutarget = path.Join(c.Chroot, q.qemusrc)
	}

	return q
}

func (q qemuHelper) Setup() error {
	if q.qemusrc == "" {
		return nil
	}
	return CopyFile(q.qemusrc, q.qemutarget, 0755)
}

func (q qemuHelper) Cleanup() {
	if q.qemusrc != "" {
		os.Remove(q.qemutarget)
	}
}
