package collect

// This file deliberately carries no build tag. Everything else in the
// package but types.go is Linux-only, and the fixed container-storage set
// is what --walk-include is validated against — by a flag parser that is
// compiled for every platform (R58), so a typo in --walk-include is
// rejected on a workstation exactly as it would be on the host.

// containerStorageRoots is the fixed set of trees the walk never enters
// (W-2): container, VM and chroot storage. The layers beneath an overlay
// live on the root filesystem and carry foreign uids and their own setuid
// files, so walking them would report an image's contents as findings of
// the host. The list is sorted, because ContainerStorageRoots is also the
// vocabulary --walk-include prints back to the operator.
//
// A path here is the conventional location only: a host that moved its
// storage (docker's data-root, podman's graphroot, containerd's root, or a
// symlink at one of these paths) is handled by the walk collector, which
// reads those configuration files and the link targets. This set is the
// part that needs no host to be known, which is why the flag parser can
// validate against it off Linux.
var containerStorageRoots = []string{
	"/var/cache/pbuilder",
	"/var/lib/cni",
	"/var/lib/containerd",
	"/var/lib/containers",
	"/var/lib/docker",
	"/var/lib/k0s",
	"/var/lib/kubelet",
	"/var/lib/libvirt/images",
	"/var/lib/lxc",
	"/var/lib/lxd",
	"/var/lib/machines",
	"/var/lib/mock",
	"/var/lib/rancher",
	"/var/lib/schroot",
	"/var/snap",
}

// ContainerStorageRoots returns the fixed container-storage set, sorted. It
// returns a copy: the caller is the walk, which subtracts --walk-include
// entries from it, and the package-level list is not the place for that.
func ContainerStorageRoots() []string {
	out := make([]string, len(containerStorageRoots))
	copy(out, containerStorageRoots)
	return out
}
