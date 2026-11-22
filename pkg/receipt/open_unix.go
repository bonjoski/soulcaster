//go:build unix

package receipt

import (
	"os"
	"syscall"
)

func openRegularNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
