package filesystem

import (
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"path/filepath"
)

// canonicalizePath turns path into an absolute path without symlinks.
func canonicalizePath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)

	// Get a better error if we have an invalid path
	if pathErr, ok := err.(*os.PathError); ok {
		err = errors.Wrap(pathErr.Err, pathErr.Path)
	}

	return path, err
}

// loggedStat runs os.Stat, but it logs the error if stat returns any error
// other than nil or IsNotExist.
func loggedStat(name string) (os.FileInfo, error) {
	info, err := os.Stat(name)
	if err != nil && !os.IsNotExist(err) {
		log.Print(err)
	}
	return info, err
}

// loggedLstat runs os.Lstat (doesn't dereference trailing symlink), but it logs
// the error if lstat returns any error other than nil or IsNotExist.
func loggedLstat(name string) (os.FileInfo, error) {
	info, err := os.Lstat(name)
	if err != nil && !os.IsNotExist(err) {
		log.Print(err)
	}
	return info, err
}

// isDir returns true if the path exists and is that of a directory.
func isDir(path string) bool {
	info, err := loggedStat(path)
	return err == nil && info.IsDir()
}

// isRegularFile returns true if the path exists and is that of a regular file.
func isRegularFile(path string) bool {
	info, err := loggedStat(path)
	return err == nil && info.Mode().IsRegular()
}

// HaveReadAccessTo returns true if the process has read access to a file or
// directory, without actually opening it.
func HaveReadAccessTo(path string) bool {
	return unix.Access(path, unix.R_OK) == nil
}

// DeviceNumber represents a combined major:minor device number.
type DeviceNumber uint64

func (num DeviceNumber) String() string {
	return fmt.Sprintf("%d:%d", unix.Major(uint64(num)), unix.Minor(uint64(num)))
}

func newDeviceNumberFromString(str string) (DeviceNumber, error) {
	var major, minor uint32
	if count, _ := fmt.Sscanf(str, "%d:%d", &major, &minor); count != 2 {
		return 0, errors.Errorf("invalid device number string %q", str)
	}
	return DeviceNumber(unix.Mkdev(major, minor)), nil
}

// getNumberOfContainingDevice returns the device number of the filesystem which
// contains the given file.  If the file is a symlink, it is not dereferenced.
func getNumberOfContainingDevice(path string) (DeviceNumber, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return 0, err
	}
	return DeviceNumber(stat.Dev), nil
}
