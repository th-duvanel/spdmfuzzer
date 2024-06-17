# Guide to setup the system on a brand-new ubuntu 20.04 installation

## Basic packages needed
```console
$ sudo apt install git build-essential cmake # build tools
$ sudo apt install libgtk-3-0-dev nettle-dev libsdl2-dev libjemalloc-dev libcap-dev libattr1-dev linux-kvm # libraries needed for QEMU
$ sudo apt install libncurses5-dev libncursesw5-dev # to enable menuconfig
$ sudo apt install flex bison # optional packages QEMU
```

## Miscellaneous configuration

* Make sure virtualization support is enabled in your BIOS

## Buildroot setup, part 1

* Download, extract, and compile Buildroot 2020.02.9
```console
$ wget https://buildroot.org/downloads/buildroot-2020.02.9.tar.bz2
$ tar xvvf buildroot-2020.02.9.tar.bz2
$ cd buildroot-2020.02.9
$ make qemu_x86_64_defconfig
$ make menuconfig
<Inside the Toolchain menu, check "Enable C++ support" option. Save and exit.>
$ make
```

## libspdm setup

libspdm have to be built two ways.

* Clone libspdm repository and checkout the correct commit
```console
$ git clone https://github.com/DMTF/libspdm.git
$ cd libspdm
$ git checkout dc48779a5b8c9199b01549311922e05429af2a0e
$ git submodule update --init --recursive
```

* Apply the patches from `libspdm_patches` and update mbedtls config file
```console
<in libspdm directory>
$ git am --3way --ignore-space-change --keep-cr /path/to/libspdm_patches/0*.patch
$ cp /path/to/libspdm_patches/config.h os_stub/mbedtlslib/include/mbedtls/
```

* For the purposes os performance analysis, it is recomended to remove any unecessary messages.
	1. Edit file libspdm/include/hal/library/debuglib.h and insert `#define MDEPKG_NDEBUG` after the guard defines
	1. Add `-Wno-error=unused-but-set-variable` flag to CMakeLists.txt to avoid compilation error (`CMAKE_C_FLAGS` variable in `if(TOOLCHAIN STREQUAL "GCC")` section)

* Increase `MAX_SPDM_MESSAGE_BUFFER_SIZE` in `libspdm/include/library/spdm_lib_config.h` to `0x2200`

* Build libspdm to be linked with QEMU (or any other applications at the host machine)
```console
<in libspdm directory>
$ mkdir build_x64
$ cd build_x64
$ cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls .. # could use -DTARGET=Debug
$ make copy_sample_key
$ make
```

* Build libspdm to be linked with the Buildroot Linux kernel
```console
<in libspdm directory>
$ mkdir build_buildroot
$ cd build_buildroot
$ cmake -DARCH=x64 -DTOOLCHAIN=BUILDROOT -DTARGET=Release -DCRYPTO=mbedtls .. # could use -DTARGET=Debug
$ export PATH=/path/to/buildroot-2020.02.9/output/host/bin:$PATH
$ make copy_sample_key
$ make
```

## Buildroot setup, part 2

* (**optional**) Enable 9p filesystem support (useful to trade files between guest and host)
```console
<in buildroot-2020.02.9 directory>
$ make linux-menuconfig
$ # Enable the following options:
$ #	Networking support -> Plan 9 Resource Sharing Support (9P2000)
$ #	Networking support -> Plan 9 Resource Sharing Support (9P2000) -> 9P Virtio Transport
$ #	File systems -> Network File Systems -> Plan 9 Resource Sharing Support (9P2000)
$ #	File systems -> Network File Systems -> Plan 9 Resource Sharing Support (9P2000) -> 9P POSIX Access Control Lists
$ #	File systems -> Network File Systems -> Plan 9 Resource Sharing Support (9P2000) -> 9P Security Labels
$ # Save and exit.
```

* Copy SPDM-related modifications to the kernel code tree
```console
cp -r /path/to/kernel_hd/drivers /path/to/buildroot-2020.02.9/output/build/linux-4.19.91/
cp -r /path/to/kernel_hd/include /path/to/buildroot-2020.02.9/output/build/linux-4.19.91/
```

* Rebuild Buildroot, indicating libspdm location
```console
$ SPDM_DIR=/path/to/libspdm SPDM_BUILD_DIR=/path/to/libspdm/build_buildroot make
```

## QEMU setup

* Clone the repository and switch to stable-4.1 branch
```
$ git clone https://github.com/qemu/qemu.git
$ cd qemu
$ git switch stable-4.1
```

* Copy new and modified files
```
$ cp -r /path/to/git/qemu_files /path/to/qemu
```

* Build qemu
```console
$ mkdir build
$ cd build
$ ../configure --enable-gtk --enable-libspdm --libspdm-srcdir=/path/to/libspdm --libspdm-builddir=/path/to/libspdm/build_x64 --libspdm-crypto=mbedtls --enable-system --enable-kvm --enable-virtfs --enable-sdl --enable-jemalloc --enable-nettle --disable-pie --enable-debug --target-list=x86_64-softmmu
$ make
```

## Running HD experiments on QEMU

* Prepare a file to be used as an additional hard drive in the VM
```console
$ dd if=/dev/zero of=benchmarkdisk bs=1M count=5000 # creates 5GB empty file. Could be larger or smaller depending on the needs
$ cfdisk benchmarkdisk # create partition table and add a linux partition occupying the whole space. Can use any other partition tool
$ mkfs.ext4 benchmarkdisk # create ext4 filesystem
```

### Running QEMU

* Run QEMU
```console
$ cd /path/to/qemu/build
$ ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu qemu64,pmu=on \
	-drive file=/path/to/benchmarkdisk,if=virtio,format=raw
	-kernel /path/to/buildroot-2020.02.9/output/images/bzImage \
	-drive file=/path/to/buildroot-2020.02.9/output/images/rootfs.ext2,if=ide,format=raw \
	-append "console=ttyS0 rootwait root=/dev/sda" \
	-m 1024 -net nic,model=virtio -net user
```

* Inside the VM, mount the virtio disk `# mkdir -p /mnt/extra_hd && mount /dev/vda /mnt/extra_hd`

* Copy `copy_test` inside the VM

* Run it as instructed in kernel_hd/benchmark/readme.md
