Name: vfs
Version: 0.1.0
Release: 1%{?dist}
Summary: S3-compatible object storage
License: Apache-2.0
BuildArch: x86_64

%description
Single-process S3-compatible object storage. The package installs a prebuilt
vfs binary and the systemd unit. Configuration is command-line arguments and
environment variables.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
install -m 0755 vfs %{buildroot}/usr/bin/vfs
install -m 0644 packaging/vfs.service %{buildroot}/usr/lib/systemd/system/vfs.service

%files
/usr/bin/vfs
/usr/lib/systemd/system/vfs.service
