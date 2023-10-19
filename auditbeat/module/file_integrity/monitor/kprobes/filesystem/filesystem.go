package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrAlreadySetup indicates that a filesystem is already setup for fscrypt.
type ErrAlreadySetup struct {
	Mount *Mount
}

func (err *ErrAlreadySetup) Error() string {
	return fmt.Sprintf("filesystem %s is already setup for use with fscrypt",
		err.Mount.Path)
}

// ErrCorruptMetadata indicates that an fscrypt metadata file is corrupt.
type ErrCorruptMetadata struct {
	Path            string
	UnderlyingError error
}

func (err *ErrCorruptMetadata) Error() string {
	return fmt.Sprintf("fscrypt metadata file at %q is corrupt: %s",
		err.Path, err.UnderlyingError)
}

// ErrFollowLink indicates that a protector link can't be followed.
type ErrFollowLink struct {
	Link            string
	UnderlyingError error
}

func (err *ErrFollowLink) Error() string {
	return fmt.Sprintf("cannot follow filesystem link %q: %s",
		err.Link, err.UnderlyingError)
}

// ErrInsecurePermissions indicates that a filesystem is not considered to be
// setup for fscrypt because a metadata directory has insecure permissions.
type ErrInsecurePermissions struct {
	Path string
}

func (err *ErrInsecurePermissions) Error() string {
	return fmt.Sprintf("%q has insecure permissions (world-writable without sticky bit)",
		err.Path)
}

// ErrMakeLink indicates that a protector link can't be created.
type ErrMakeLink struct {
	Target          *Mount
	UnderlyingError error
}

func (err *ErrMakeLink) Error() string {
	return fmt.Sprintf("cannot create filesystem link to %q: %s",
		err.Target.Path, err.UnderlyingError)
}

// ErrMountOwnedByAnotherUser indicates that the mountpoint root directory is
// owned by a user that isn't trusted in the current context, so we don't
// consider fscrypt to be properly setup on the filesystem.
type ErrMountOwnedByAnotherUser struct {
	Mount *Mount
}

func (err *ErrMountOwnedByAnotherUser) Error() string {
	return fmt.Sprintf("another non-root user owns the root directory of %s", err.Mount.Path)
}

// ErrNoCreatePermission indicates that the current user lacks permission to
// create fscrypt metadata on the given filesystem.
type ErrNoCreatePermission struct {
	Mount *Mount
}

func (err *ErrNoCreatePermission) Error() string {
	return fmt.Sprintf("user lacks permission to create fscrypt metadata on %s", err.Mount.Path)
}

// ErrNotAMountpoint indicates that a path is not a mountpoint.
type ErrNotAMountpoint struct {
	Path string
}

func (err *ErrNotAMountpoint) Error() string {
	return fmt.Sprintf("%q is not a mountpoint", err.Path)
}

// ErrNotSetup indicates that a filesystem is not setup for fscrypt.
type ErrNotSetup struct {
	Mount *Mount
}

func (err *ErrNotSetup) Error() string {
	return fmt.Sprintf("filesystem %s is not setup for use with fscrypt", err.Mount.Path)
}

// ErrSetupByAnotherUser indicates that one or more of the fscrypt metadata
// directories is owned by a user that isn't trusted in the current context, so
// we don't consider fscrypt to be properly setup on the filesystem.
type ErrSetupByAnotherUser struct {
	Mount *Mount
}

func (err *ErrSetupByAnotherUser) Error() string {
	return fmt.Sprintf("another non-root user owns fscrypt metadata directories on %s", err.Mount.Path)
}

// ErrSetupNotSupported indicates that the given filesystem type is not
// supported for fscrypt setup.
type ErrSetupNotSupported struct {
	Mount *Mount
}

func (err *ErrSetupNotSupported) Error() string {
	return fmt.Sprintf("filesystem type %s is not supported for fscrypt setup",
		err.Mount.FilesystemType)
}

// ErrPolicyNotFound indicates that the policy metadata was not found.
type ErrPolicyNotFound struct {
	Descriptor string
	Mount      *Mount
}

func (err *ErrPolicyNotFound) Error() string {
	return fmt.Sprintf("policy metadata for %s not found on filesystem %s",
		err.Descriptor, err.Mount.Path)
}

// ErrProtectorNotFound indicates that the protector metadata was not found.
type ErrProtectorNotFound struct {
	Descriptor string
	Mount      *Mount
}

func (err *ErrProtectorNotFound) Error() string {
	return fmt.Sprintf("protector metadata for %s not found on filesystem %s",
		err.Descriptor, err.Mount.Path)
}

// SortDescriptorsByLastMtime indicates whether descriptors are sorted by last
// modification time when being listed.  This can be set to true to get
// consistent output for testing.
var SortDescriptorsByLastMtime = false

// Mount contains information for a specific mounted filesystem.
//
//	Path           - Absolute path where the directory is mounted
//	FilesystemType - Type of the mounted filesystem, e.g. "ext4"
//	Device         - Device for filesystem (empty string if we cannot find one)
//	DeviceNumber   - Device number of the filesystem.  This is set even if
//			 Device isn't, since all filesystems have a device
//			 number assigned by the kernel, even pseudo-filesystems.
//	Subtree        - The mounted subtree of the filesystem.  This is usually
//			 "/", meaning that the entire filesystem is mounted, but
//			 it can differ for bind mounts.
//	ReadOnly       - True if this is a read-only mount
type Mount struct {
	Path           string
	FilesystemType string
	Device         string
	DeviceNumber   DeviceNumber
	Subtree        string
	ReadOnly       bool
}

// PathSorter allows mounts to be sorted by Path.
type PathSorter []*Mount

func (p PathSorter) Len() int           { return len(p) }
func (p PathSorter) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PathSorter) Less(i, j int) bool { return p[i].Path < p[j].Path }

const (
	// Names of the various directories used in fscrypt
	baseDirName       = ".fscrypt"
	policyDirName     = "policies"
	protectorDirName  = "protectors"
	tempPrefix        = ".tmp"
	linkFileExtension = ".link"

	// The base directory should be read-only (except for the creator)
	basePermissions = 0755

	// The metadata files shouldn't be readable or writable by other users.
	// Having them be world-readable wouldn't necessarily be a huge issue,
	// but given that some of these files contain (strong) password hashes,
	// we error on the side of caution -- similar to /etc/shadow.
	// Note: existing files on-disk might have mode 0644, as that was the
	// mode used by fscrypt v0.3.2 and earlier.
	filePermissions = os.FileMode(0600)

	// Maximum size of a metadata file.  This value is arbitrary, and it can
	// be changed.  We just set a reasonable limit that shouldn't be reached
	// in practice, except by users trying to cause havoc by creating
	// extremely large files in the metadata directories.
	maxMetadataFileSize = 16384
)

// SetupMode is a mode for creating the fscrypt metadata directories.
type SetupMode int

const (
	// SingleUserWritable specifies to make the fscrypt metadata directories
	// writable by a single user (usually root) only.
	SingleUserWritable SetupMode = iota
	// WorldWritable specifies to make the fscrypt metadata directories
	// world-writable (with the sticky bit set).
	WorldWritable
)

func (m *Mount) String() string {
	return fmt.Sprintf(`%s
	FilesystemType: %s
	Device:         %s`, m.Path, m.FilesystemType, m.Device)
}

// BaseDir returns the path to the base fscrypt directory for this filesystem.
func (m *Mount) BaseDir() string {
	rawBaseDir := filepath.Join(m.Path, baseDirName)
	// We allow the base directory to be a symlink, but some callers need
	// the real path, so dereference the symlink here if needed. Since the
	// directory the symlink points to may not exist yet, we have to read
	// the symlink manually rather than use filepath.EvalSymlinks.
	target, err := os.Readlink(rawBaseDir)
	if err != nil {
		return rawBaseDir // not a symlink
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(m.Path, target)
}

// ErrEncryptionNotEnabled indicates that encryption is not enabled on the given
// filesystem.
type ErrEncryptionNotEnabled struct {
	Mount *Mount
}

func (err *ErrEncryptionNotEnabled) Error() string {
	return fmt.Sprintf("encryption not enabled on filesystem %s (%s).",
		err.Mount.Path, err.Mount.Device)
}

// ErrEncryptionNotSupported indicates that encryption is not supported on the
// given filesystem.
type ErrEncryptionNotSupported struct {
	Mount *Mount
}

func (err *ErrEncryptionNotSupported) Error() string {
	return fmt.Sprintf("This kernel doesn't support encryption on %s filesystems.",
		err.Mount.FilesystemType)
}

type namesAndTimes struct {
	names []string
	times []time.Time
}

func (c namesAndTimes) Len() int {
	return len(c.names)
}

func (c namesAndTimes) Less(i, j int) bool {
	return c.times[i].Before(c.times[j])
}

func (c namesAndTimes) Swap(i, j int) {
	c.names[i], c.names[j] = c.names[j], c.names[i]
	c.times[i], c.times[j] = c.times[j], c.times[i]
}

func sortFileListByLastMtime(directoryPath string, names []string) error {
	c := namesAndTimes{names: names, times: make([]time.Time, len(names))}
	for i, name := range names {
		fi, err := os.Lstat(filepath.Join(directoryPath, name))
		if err != nil {
			return err
		}
		c.times[i] = fi.ModTime()
	}
	sort.Sort(c)
	return nil
}

// listDirectory returns a list of descriptors for a metadata directory,
// including files which are links to other filesystem's metadata.
func (m *Mount) listDirectory(directoryPath string) ([]string, error) {
	dir, err := os.Open(directoryPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	if SortDescriptorsByLastMtime {
		if err := sortFileListByLastMtime(directoryPath, names); err != nil {
			return nil, err
		}
	}

	descriptors := make([]string, 0, len(names))
	for _, name := range names {
		// Be sure to include links as well
		descriptors = append(descriptors, strings.TrimSuffix(name, linkFileExtension))
	}
	return descriptors, nil
}
