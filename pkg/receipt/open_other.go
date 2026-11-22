//go:build !unix

package receipt

import "os"

func openRegularNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
