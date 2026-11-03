#!/usr/bin/env python3 -tt
import glob
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

from dernvale.audit import write_audit_log_entry
from dernvale.core.identify import identify_disk_image
from dernvale.utils import safe_input



def _run_quietly(cmd):
    """Run a teardown command; (returncode, stdout). A missing tool is (127, "")."""
    try:
        done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return done.returncode, done.stdout
    except OSError:
        return 127, ""


def release_loop_devices():
    """Detach every loop device a job left behind, kpartx's included.

    `losetup -D` alone can't detach a loop device kpartx has mapped partitions onto
    (/dev/mapper/loopNpM hold it open), so the next Linux job found its mount busy
    and finished with nothing (E9). The partition mappings go first: unmounted
    wherever they're still mounted, then removed (kpartx -d, dmsetup as a fallback).
    Returns the loop devices still attached afterwards, which are reported."""
    mapped = sorted(glob.glob("/dev/mapper/loop*p*"))
    for part in mapped:
        _run_quietly(["umount", part])
    loops = sorted({re.sub(r"p\d+$", "", os.path.basename(m)) for m in mapped})
    for loop in loops:
        _run_quietly(["kpartx", "-d", "/dev/" + loop])
    for part in mapped:
        if os.path.exists(part):
            _run_quietly(["dmsetup", "remove", os.path.basename(part)])
    _run_quietly(["losetup", "-D"])
    code, attached = _run_quietly(["losetup", "-a"])
    left = [line.split(":", 1)[0] for line in attached.splitlines() if line.strip()] if code == 0 else []
    if left:
        print("   Warning: loop devices still attached after unmounting: {}".format(", ".join(left)))
    return left


def cleanup_stale_mounts(elrond_mount, ewf_mount):
    """
    Unmount any stale mounts without removing directories.
    Use this at the start of a job to ensure clean state.
    """
    def unmount_location(each):
        subprocess.Popen(
            ["umount", each], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).communicate()
        time.sleep(0.1)

    # Unmount shadow mounts
    if os.path.exists("/mnt/shadow_mount/"):
        for shadowimg in os.listdir("/mnt/shadow_mount/"):
            for everyshadow in os.listdir("/mnt/shadow_mount/" + shadowimg):
                unmount_location("/mnt/shadow_mount/" + shadowimg + "/" + everyshadow)

    # Unmount VSS mounts
    if os.path.exists("/mnt/vss/"):
        for eachimg in os.listdir("/mnt/vss/"):
            for eachvss in os.listdir("/mnt/vss/" + eachimg):
                if os.path.exists("/mnt/vss/" + eachimg + "/" + eachvss):
                    unmount_location("/mnt/vss/" + eachimg + "/" + eachvss)
            if os.path.exists("/mnt/vss/" + eachimg):
                unmount_location("/mnt/vss/" + eachimg)

    # Disconnect NBD devices
    for devnbd in range(1, 15):
        if os.path.exists("/dev/nbd" + str(devnbd)):
            unmount_location("/dev/nbd" + str(devnbd))
            subprocess.Popen(
                ["qemu-nbd", "--disconnect", "/dev/nbd" + str(devnbd)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()

    # Unmount elrond mounts (but don't remove directories)
    for eachelrond in elrond_mount:
        if os.path.exists(eachelrond):
            unmount_location(eachelrond)

    # Unmount EWF mounts (but don't remove directories)
    for eachewf in ewf_mount:
        if os.path.exists(eachewf):
            unmount_location(eachewf + "/")

    release_loop_devices()


def unmount_images(elrond_mount, ewf_mount):
    def unmount_locations(each):
        subprocess.Popen(
            ["umount", each], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).communicate()
        time.sleep(0.1)

    def remove_directories(each):
        try:
            shutil.rmtree(each)
        except PermissionError:
            print(
                "\n   Error: Unable to unmount locations. Are you running elrond as root?\n\n"
            )
            sys.exit()
        except OSError as e:
            # Handle read-only file system errors gracefully
            if e.errno == 30:  # EROFS - Read-only file system
                print(f"   Warning: Unable to remove directory {each} (read-only file system)")
            else:
                print(f"   Warning: Unable to remove directory {each}: {e}")
        time.sleep(0.1)

    # Check if shadow_mount directory exists before accessing
    if os.path.exists("/mnt/shadow_mount/"):
        for shadowimg in os.listdir("/mnt/shadow_mount/"):
            for everyshadow in os.listdir("/mnt/shadow_mount/" + shadowimg):
                unmount_locations("/mnt/shadow_mount/" + shadowimg + "/" + everyshadow)
            remove_directories("/mnt/shadow_mount/" + shadowimg)

    # Check if vss directory exists before accessing
    if os.path.exists("/mnt/vss/"):
        for eachimg in os.listdir("/mnt/vss/"):
            for eachvss in os.listdir("/mnt/vss/" + eachimg):
                if os.path.exists("/mnt/vss/" + eachimg + "/" + eachvss):
                    unmount_locations("/mnt/vss/" + eachimg + "/" + eachvss)
            if os.path.exists("/mnt/vss/" + eachimg):
                unmount_locations("/mnt/vss/" + eachimg)
                remove_directories("/mnt/vss/" + eachimg)
    for devnbd in range(1, 15):
        if os.path.exists("/dev/nbd" + str(devnbd)):
            unmount_locations("/dev/nbd" + str(devnbd))
            subprocess.Popen(
                [
                    "qemu-nbd",
                    "--disconnect",
                    "/dev/nbd" + str(devnbd),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
    for eachelrond in elrond_mount:
        if os.path.exists(eachelrond):
            unmount_locations(eachelrond)
            remove_directories(eachelrond)
    for eachewf in ewf_mount:
        if os.path.exists(eachewf):
            unmount_locations(eachewf + "/")
            if eachewf != "/mnt/ewf_mount":
                remove_directories(eachewf)

    release_loop_devices()


def collect_ewfinfo(elrond_mount, ewf_mount, path, intermediate_mount, cwd):
    ewfinfo = list(
        re.findall(
            r"ewfinfo[^\\]+\\n\\n.*Acquisition\sdate\:\\t(?P<aquisition_date>[^\\]+)\\n.*Operating\ssystem\sused\:\\t(?P<os_used>[^\\]+)\\n.*Sectors\sper\schunk\:\\t(?P<sector_chunks>[^\\]+)\\n.*Bytes\sper\ssector\:\\t(?P<bps>[^\\]+)\\n\\tNumber\sof\ssectors\:\\t(?P<nos>[^\\]+)\\n\\tMedia\ssize\:\\t\\t(?P<media_size>[^\\]+)\\n",
            str(
                subprocess.Popen(
                    ["ewfinfo", path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            ),
        )[0]
    )
    os.chdir(intermediate_mount)
    mount_ewf(path, intermediate_mount + "/")
    rawinfo = list(
        re.findall(
            r"Disk\sidentifier\:\s(?P<rawdiskid>[^\\]+)\\n",
            str(
                subprocess.Popen(
                    ["fdisk", "-l", "ewf1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-3],
        )[0]
    )
    print(
        "\n  -> Information for '{}'\n\n   Acquisition date/time:\t{}\n   Operating system:\t\t{}\n   Image size:\t\t\t{}\n   Identifier:\t\t\t{}\n   No. of sectors:\t\t{}\n   Size of sector chunks:\t{}\n   Bytes per sector:\t\t{}\n".format(
            path,
            ewfinfo[0],
            ewfinfo[1],
            ewfinfo[5],
            rawinfo[0],
            ewfinfo[2],
            ewfinfo[3],
            ewfinfo[4],
        )
    )
    os.chdir(cwd)
    conelrond = safe_input(
        "    Typically, the --information flag is used before forensic analysis commences.\n     Do you want to continue with the forensic analysis? Y/n [Y] ",
        default="y"
    )
    if conelrond == "n":
        unmount_images(elrond_mount, ewf_mount)
        sys.exit()


def obtain_offset(
    intermediate_mount,
):
    offset_values = re.findall(
        r"\\n[\w\-\.\/]+(?:(?:(?:ewf1|nbd\d)p\d+)|\.(?:raw|dd|img)\d)[\ \*]+(?P<offset>\d+)[\w\d\.\ \*]+\s+(?:NTFS|Microsoft\ basic\ data|HPFS|Linux|exFAT)",
        str(
            subprocess.Popen(
                ["fdisk", "-l", intermediate_mount],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )[2:-3],
    )
    return offset_values


def mounted_image(allimgs, disk_image, destination_mount, disk_file, index):
    # Convert index to int for comparison if it's a string number
    try:
        idx = int(index) if isinstance(index, str) and index != "0" else index
    except ValueError:
        idx = index

    if index == "0":
        partition = ""
    elif idx == 0:
        partition = " (zeroth partition)"
    elif idx == 1:
        partition = " (first partition)"
    elif idx == 2:
        partition = " (second partition)"
    elif idx == 3:
        partition = " (third partition)"
    elif idx == 4:
        partition = " (forth partition)"
    elif idx == 5:
        partition = " (fifth partition)"
    elif idx == 6:
        partition = " (sixth partition)"
    elif idx == 7:
        partition = " (seventh partition)"
    elif idx == 8:
        partition = " (eighth partition)"
    elif idx == 9:
        partition = " (ninth partition)"
    else:
        partition = f" (partition {idx})"
    if "::Windows" in disk_image or "::macOS" in disk_image or "::Linux" in disk_image:
        allimgs[destination_mount] = disk_image
        print(
            "   Mounted '{}'{} successfully at '{}'".format(
                disk_file, partition, destination_mount
            )
        )
    else:
        print("   '{}'{} could not be mounted.".format(disk_image, partition))
    return partition


def _try_guestmount(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
    """
    Try to mount a disk image using guestmount (libguestfs).
    This is a FUSE-based solution that works in Docker without loop devices.
    It can automatically detect and mount partitions from various disk image formats.
    """
    try:
        # Check if guestmount is available
        which_result = subprocess.run(
            ["which", "guestmount"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        if which_result.returncode != 0:
            return False

        print(f"  -> Trying guestmount for {disk_file}...")

        # First, list partitions using virt-filesystems
        virt_fs_result = subprocess.run(
            ["virt-filesystems", "-a", path, "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )

        if virt_fs_result.returncode != 0:
            # virt-filesystems may fail, try guestmount directly with inspection
            pass

        # Try guestmount with automatic inspection (mounts the largest/main partition)
        guestmount_result = subprocess.run(
            ["guestmount", "-a", path, "-i", "--ro", destination_mount],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )

        if guestmount_result.returncode == 0:
            # Check if mount succeeded (destination should have files)
            if os.path.exists(destination_mount) and os.listdir(destination_mount):
                print(f"  -> Successfully mounted {disk_file} via guestmount")
                disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, "0")
                partitions.append(f"{partition}||{disk_image}")
                return True

        # If automatic inspection failed, try mounting specific partitions
        # Parse virt-filesystems output to find mountable partitions
        if virt_fs_result.returncode == 0 and virt_fs_result.stdout:
            for line in virt_fs_result.stdout.strip().split('\n'):
                if '/dev/' in line:
                    parts = line.split()
                    if parts:
                        dev_name = parts[0]  # e.g., /dev/sda1
                        # Try mounting this partition
                        gm_result = subprocess.run(
                            ["guestmount", "-a", path, "-m", dev_name, "--ro", destination_mount],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=120
                        )
                        if gm_result.returncode == 0 and os.listdir(destination_mount):
                            print(f"  -> Successfully mounted {dev_name} from {disk_file} via guestmount")
                            disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                            partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, "0")
                            partitions.append(f"{partition}||{disk_image}")
                            return True

        return False

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  -> guestmount failed: {e}")
        return False
    except Exception as e:
        print(f"  -> guestmount error: {e}")
        return False


def _check_nbd_available():
    """Check if nbd kernel module is available and functional."""
    try:
        # First try to load the nbd module
        result = subprocess.run(
            ["modprobe", "nbd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        # modprobe must succeed (exit code 0)
        if result.returncode != 0:
            return False
        # Check if any /dev/nbd* devices exist after modprobe
        import glob
        return len(glob.glob("/dev/nbd*")) > 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _mount_with_kpartx(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
    """Mount raw/dd image using kpartx (fallback when nbd unavailable)."""
    print(f"  -> Using kpartx to mount {disk_file}...")

    # Use kpartx to create loop device mappings
    kpartx_result = subprocess.run(
        ["kpartx", "-av", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if kpartx_result.returncode != 0:
        print(f"  -> kpartx failed: {kpartx_result.stderr}")
        return False

    # Parse kpartx output to find created loop devices
    # Output format: "add map loopXpY (253:Z): 0 SECTORS linear /dev/loopX OFFSET"
    import re
    loop_devices = re.findall(r'add map (loop\d+p\d+)', kpartx_result.stdout)

    if not loop_devices:
        # Try direct loop mount for single-partition images
        print(f"  -> No partitions found, trying direct loop mount...")
        # Extended filesystem list including macOS HFS+
        for fs_type in ["ext4", "ntfs", "xfs", "exfat", "hfsplus"]:
            if fs_type == "ext4":
                mount_opts = "ro,norecovery,loop"
            elif fs_type == "ntfs":
                mount_opts = "ro,loop,show_sys_files,streams_interface=windows"
            elif fs_type == "xfs":
                mount_opts = "ro,norecovery,loop"
            else:
                mount_opts = "ro,loop"

            mount_result = subprocess.run(
                ["mount", "-t", fs_type, "-o", mount_opts, path, destination_mount],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if mount_result.returncode == 0:
                print(f"  -> Successfully mounted as {fs_type}")
                disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, "0")
                partitions.append(f"{partition}||{disk_image}")
                return True

        # Try APFS with apfs-fuse (macOS 10.13+)
        try:
            apfs_result = subprocess.run(
                ["/usr/local/bin/apfs-fuse", "-o", "allow_other", path, destination_mount],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if apfs_result.returncode == 0:
                print(f"  -> Successfully mounted as APFS (via apfs-fuse)")
                disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, "0")
                partitions.append(f"{partition}||{disk_image}")
                return True
        except FileNotFoundError:
            pass  # apfs-fuse not installed

        # Try guestmount for partitioned images (works in Docker without loop devices)
        if _try_guestmount(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
            return True

        return False

    # Mount each partition found by kpartx
    mounted_any = False
    for idx, loop_dev in enumerate(loop_devices):
        dev_path = f"/dev/mapper/{loop_dev}"

        # Try different filesystem types including macOS HFS+
        for fs_type in ["ntfs", "ext4", "xfs", "exfat", "hfsplus"]:
            if fs_type == "ext4":
                mount_opts = "ro,norecovery"
            elif fs_type == "ntfs":
                mount_opts = "ro,show_sys_files,streams_interface=windows"
            elif fs_type == "xfs":
                mount_opts = "ro,norecovery"
            else:
                mount_opts = "ro"

            mount_result = subprocess.run(
                ["mount", "-t", fs_type, "-o", mount_opts, dev_path, destination_mount],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if mount_result.returncode == 0:
                print(f"  -> Partition {idx} mounted as {fs_type}")
                disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, str(idx))
                partitions.append(f"{partition}||{disk_image}")
                mounted_any = True
                break

    return mounted_any


def mount_vmdk_image(
    verbosity,
    output_directory,
    intermediate_mount,
    destination_mount,
    disk_file,
    path,
    allimgs,
    partitions,
):
    # Check if nbd is available (won't work in Docker containers)
    nbd_available = _check_nbd_available()

    if not nbd_available:
        # Use kpartx-based mounting (works in Docker without kernel modules)
        print(f"  -> nbd unavailable (Docker environment), using kpartx for {disk_file}...")
        if _mount_with_kpartx(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
            return partitions
        else:
            print(f"  -> kpartx mounting failed for {disk_file}")
            # Try guestmount as final fallback
            if _try_guestmount(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
                return partitions
            print(f"   '{disk_file}' could not be mounted (no working mount method available)")
            return partitions

    # Try apfs-fuse first for APFS volumes (installed in Docker container)
    try:
        subprocess.Popen(
            [
                "/usr/local/bin/apfs-fuse",
                "-o",
                "allow_other",
                intermediate_mount,
                destination_mount,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    except:
        # apfs-fuse may not be installed or may fail
        pass

    # Try nbd-based mounting (original logic - only if nbd is available)
    subprocess.Popen(
        [
            "modprobe",
            "nbd",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    for devnbd in range(1, 15):  # check for first empty /dev/ndbX location
        validfile = str(
            subprocess.Popen(
                ["fdisk", "-l", "/dev/nbd" + str(devnbd)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        )
        if "Inappropriate ioctl for device" in validfile:
            intermediate_mount = "/dev/nbd" + str(devnbd)
            break
    subprocess.Popen(
        [
            "qemu-nbd",
            "-r",
            "-c",
            intermediate_mount,
            path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    offset_values = obtain_offset(intermediate_mount)
    if len(offset_values) > 0:
        for offset_value in offset_values:
            if (
                str(
                    subprocess.Popen(
                        [
                            "mount",
                            "-t",
                            "ext4",
                            "-o",
                            "ro,norecovery,loop,offset="
                            + str(int(offset_value) * 512),
                            intermediate_mount,
                            destination_mount,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[1]
                )
                == "b''"
            ):
                disk_image = identify_disk_image(
                    verbosity, output_directory, disk_file, destination_mount
                )
                partition = mounted_image(
                    allimgs, disk_image, destination_mount, disk_file, "0"
                )
                partitions.append(
                    "{}||{}".format(
                        partition[2:-1]
                        .replace("partition", "")
                        .replace("zeroth", "00zeroth")
                        .replace("first", "01first")
                        .replace("second", "02second")
                        .replace("third", "03third")
                        .replace("forth", "04forth")
                        .replace("fifth", "05fifth")
                        .replace("sixth", "06sixth")
                        .replace("seventh", "07seventh")
                        .replace("eighth", "08eighth")
                        .replace("ninth", "09ninth")
                        .strip(),
                        disk_image,
                    )
                )
            elif (
                str(
                    subprocess.Popen(
                        [
                            "mount",
                            "-t",
                            "ntfs",
                            "-o",
                            "ro,loop,show_sys_files,streams_interface=windows,offset="
                            + str(int(offset_value) * 512),
                            intermediate_mount,
                            destination_mount,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[1]
                )
                == "b''"
            ):
                disk_image = identify_disk_image(
                    verbosity, output_directory, disk_file, destination_mount
                )
                partition = mounted_image(
                    allimgs, disk_image, destination_mount, disk_file, "0"
                )
                partitions.append(
                    "{}||{}".format(
                        partition[2:-1]
                        .replace("partition", "")
                        .replace("zeroth", "00zeroth")
                        .replace("first", "01first")
                        .replace("second", "02second")
                        .replace("third", "03third")
                        .replace("forth", "04forth")
                        .replace("fifth", "05fifth")
                        .replace("sixth", "06sixth")
                        .replace("seventh", "07seventh")
                        .replace("eighth", "08eighth")
                        .replace("ninth", "09ninth")
                        .strip(),
                        disk_image,
                    )
                )
            else:
                mount_attempt = str(
                    subprocess.Popen(
                        [
                            "mount",
                            "-o",
                            "ro,loop,show_sys_files,streams_interface=windows,offset="
                            + str(int(offset_value) * 512),
                            intermediate_mount,
                            destination_mount,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[1]
                )
                if mount_attempt == "b''":
                    disk_image = identify_disk_image(
                        verbosity, output_directory, disk_file, destination_mount
                    )
                    partition = mounted_image(
                        allimgs, disk_image, destination_mount, disk_file, "0"
                    )
                    partitions.append(
                        "{}||{}".format(
                            partition[2:-1]
                            .replace("partition", "")
                            .replace("zeroth", "00zeroth")
                            .replace("first", "01first")
                            .replace("second", "02second")
                            .replace("third", "03third")
                            .replace("forth", "04forth")
                            .replace("fifth", "05fifth")
                            .replace("sixth", "06sixth")
                            .replace("seventh", "07seventh")
                            .replace("eighth", "08eighth")
                            .replace("ninth", "09ninth")
                            .strip(),
                            disk_image,
                        )
                    )
                elif (
                    "overlapping loop device exists" in mount_attempt
                ):  # mounted the first valid partition, but cannot mount another partition in the same way
                    nbd_mount = re.findall(
                        r"\\n[\w\-\.\/]+(nbd\dp\d+)|\.(?:raw|dd|img)\d[\ \*]+(?:\d+)[\w\d\.\ \*]+\s+(?:NTFS|Microsoft\ basic\ data|HPFS|Linux|exFAT)",
                        str(
                            subprocess.Popen(
                                ["fdisk", "-l", intermediate_mount],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()[0]
                        )[2:-3],
                    )
                    nbd_mount.pop(0)
                    for eachnbd in nbd_mount:
                        if len(os.listdir(destination_mount)) > 0:
                            new_destination = int(
                                re.findall(
                                    r"elrond_mount0?(\d+)", destination_mount
                                )[0]
                            )
                            new_destination += 1
                            if len(str(new_destination)) == 1:
                                new_destination = "/mnt/elrond_mount0" + str(
                                    new_destination
                                )
                            else:
                                new_destination = "/mnt/elrond_mount" + str(
                                    new_destination
                                )
                            if not os.path.exists(new_destination):
                                os.mkdir(new_destination)
                            destination_mount = new_destination + "/"
                            subprocess.Popen(
                                ["mount", "/dev/" + eachnbd, destination_mount],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()[
                                0
                            ]  # to mount VMDKs - sudo mount /dev/nbd1p2 /mnt/elrond_mount01/
                            disk_image = identify_disk_image(
                                verbosity,
                                output_directory,
                                disk_file,
                                destination_mount,
                            )
                            partition = mounted_image(
                                allimgs,
                                disk_image,
                                destination_mount,
                                disk_file,
                                "0",
                            )
                            partitions.append(
                                "{}||{}".format(
                                    partition[2:-1]
                                    .replace("partition", "")
                                    .replace("zeroth", "00zeroth")
                                    .replace("first", "01first")
                                    .replace("second", "02second")
                                    .replace("third", "03third")
                                    .replace("forth", "04forth")
                                    .replace("fifth", "05fifth")
                                    .replace("sixth", "06sixth")
                                    .replace("seventh", "07seventh")
                                    .replace("eighth", "08eighth")
                                    .replace("ninth", "09ninth")
                                    .strip(),
                                    disk_image,
                                )
                            )
                elif (
                    "unknown filesystem type 'swap'" in mount_attempt
                ):  # cannot mount swap partition
                    pass
                else:
                    print(
                        "   An error occured when mounting '{}'.\n    Perhaps this is a macOS-based image and requires apfs-fuse (https://github.com/cyberg3cko/apfs-fuse)?\n    Alternatively, the disk may not be supported and/or may be corrupt? You can raise an issue via https://github.com/cyberg3cko/elrond/issues".format(
                            disk_file
                        )
                    )
                    if os.path.exists(
                        os.path.join(
                            output_directory, intermediate_mount.split("/")[-1]
                        )
                    ):
                        os.remove(
                            os.path.join(
                                output_directory, intermediate_mount.split("/")[-1]
                            )
                            + "/dernvale_audit.log"
                        )
                        os.rmdir(
                            os.path.join(
                                output_directory, intermediate_mount.split("/")[-1]
                            )
                        )
    else:
        disk_image = identify_disk_image(
            verbosity, output_directory, disk_file, destination_mount
        )
        partition = mounted_image(
            allimgs, disk_image, destination_mount, disk_file, "0"
        )
        partitions.append(
            "{}||{}".format(
                partition[2:-1]
                .replace("partition", "")
                .replace("zeroth", "00zeroth")
                .replace("first", "01first")
                .replace("second", "02second")
                .replace("third", "03third")
                .replace("forth", "04forth")
                .replace("fifth", "05fifth")
                .replace("sixth", "06sixth")
                .replace("seventh", "07seventh")
                .replace("eighth", "08eighth")
                .replace("ninth", "09ninth")
                .strip(),
                disk_image,
            )
        )
    return partitions


# The raw device ewfmount exposes for each EWF image, so carving reads the media,
# not the compressed container (E8)
EWF_RAW = {}


def mount_ewf(path, intermediate_mount):
    subprocess.Popen(
        ["ewfmount", path, intermediate_mount],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[1],
    EWF_RAW[os.path.realpath(path)] = os.path.join(intermediate_mount, "ewf1")


def ewf_raw(path):
    """The mounted raw media of an EWF image, or None when it isn't mounted. Matched
    by name when the path differs (carving names images from the source root, but
    they may sit in a subdirectory of it)."""
    raw = EWF_RAW.get(os.path.realpath(path))
    if raw is None:
        named = [r for src, r in EWF_RAW.items() if os.path.basename(src) == os.path.basename(path)]
        raw = named[0] if len(named) == 1 else None
    return raw if raw and os.path.exists(raw) else None


def mount_images(
    d,
    auto,
    verbosity,
    output_directory,
    path,
    disk_file,
    elrond_mount,
    ewf_mount,
    allimgs,
    imgformat,
    vss,
    stage,
    cwd,
    quotes,
    partitions,
):
    if not os.path.exists(elrond_mount[0]):
        try:
            os.makedirs(elrond_mount[0])
        except:
            print(
                "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root', please try again...\n\n".format(
                    elrond_mount[0], disk_file.split("::")[0]
                )
            )
            sys.exit()
    if len(os.listdir(elrond_mount[0])) != 0:
        elrond_mount.pop(0)
        allimgs, partitions = mount_images(
            d,
            auto,
            verbosity,
            output_directory,
            path,
            disk_file,
            elrond_mount,
            ewf_mount,
            allimgs,
            imgformat,
            vss,
            stage,
            cwd,
            quotes,
            partitions,
        )
        # Return after recursive call to avoid falling through to else block
        return allimgs, partitions
    else:  # mounting images
        if "EWF" in imgformat or "Expert Witness" in imgformat:
            if not os.path.exists(ewf_mount[0]):
                try:
                    os.makedirs(ewf_mount[0])
                except:
                    print(
                        "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root', please try again...\n\n".format(
                            ewf_mount[0], disk_file.split("::")[0]
                        )
                    )
                    sys.exit()
            if len(os.listdir(ewf_mount[0])) != 0:
                ewf_mount.pop(0)
                allimgs, partitions = mount_images(
                    d,
                    auto,
                    verbosity,
                    output_directory,
                    path,
                    disk_file,
                    elrond_mount,
                    ewf_mount,
                    allimgs,
                    imgformat,
                    vss,
                    stage,
                    cwd,
                    quotes,
                    partitions,
                )
                # Return after recursive call to avoid falling through to mount code below
                return allimgs, partitions
            destination_mount, intermediate_mount = elrond_mount[0], ewf_mount[0]
            mount_ewf(path, intermediate_mount)

            # Try multiple filesystem types for E01 images
            # Order: NTFS (Windows), HFS+ (macOS), ext4 (Linux), XFS (Linux)
            mount_attempts = [
                # NTFS for Windows
                ("ntfs", ["mount", "-o", "ro,loop,show_sys_files,streams_interface=windows",
                          intermediate_mount + "/ewf1", destination_mount]),
                # HFS+ for older macOS
                ("hfsplus", ["mount", "-t", "hfsplus", "-o", "ro,loop",
                             intermediate_mount + "/ewf1", destination_mount]),
                # ext4 for Linux
                ("ext4", ["mount", "-t", "ext4", "-o", "ro,loop,norecovery",
                          intermediate_mount + "/ewf1", destination_mount]),
                # XFS for Linux
                ("xfs", ["mount", "-t", "xfs", "-o", "ro,loop,norecovery",
                         intermediate_mount + "/ewf1", destination_mount]),
            ]

            mounterr = "mount_not_attempted"
            mounted_fs_type = None
            for fs_type, mount_cmd in mount_attempts:
                mounterr = str(
                    subprocess.Popen(
                        mount_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[1]
                )
                if mounterr == "b''":
                    mounted_fs_type = fs_type
                    break
                # Unmount if partial mount happened
                subprocess.Popen(["umount", destination_mount],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

            # If standard loop mounts failed, try FUSE-based mounting
            # This is needed in Docker containers where loop mounts on FUSE-exposed files fail
            if mounterr != "b''":
                ewf1_path = intermediate_mount + "/ewf1"

                # Try NTFS via ntfs-3g (FUSE-based, works in Docker)
                try:
                    ntfs3g_result = subprocess.run(
                        ["ntfs-3g", "-o", "ro,allow_other,streams_interface=windows",
                         ewf1_path, destination_mount],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=60
                    )
                    if ntfs3g_result.returncode == 0:
                        mounterr = "b''"
                        mounted_fs_type = "ntfs-3g"
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass

            # Try ext4 via fuse2fs if available
            if mounterr != "b''":
                print(f"    Trying fuse2fs for ext4 filesystem on {ewf1_path}...")
                try:
                    fuse2fs_result = subprocess.run(
                        ["fuse2fs", "-o", "ro,allow_other,fakeroot",
                         ewf1_path, destination_mount],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=60
                    )
                    if fuse2fs_result.returncode == 0:
                        mounterr = "b''"
                        mounted_fs_type = "ext4-fuse"
                        print(f"    Mounted E01 as ext4 filesystem (via fuse2fs)")
                    else:
                        stderr_msg = fuse2fs_result.stderr.decode('utf-8', errors='ignore').strip()[:200]
                        print(f"    fuse2fs failed (exit code {fuse2fs_result.returncode}): {stderr_msg}")
                except FileNotFoundError:
                    print("    fuse2fs not found - cannot mount ext4 filesystems")
                except subprocess.TimeoutExpired:
                    print("    fuse2fs timed out after 60 seconds")
                except Exception as e:
                    print(f"    fuse2fs error: {e}")

            # Try APFS with apfs-fuse (macOS 10.13+)
            if mounterr != "b''":
                try:
                    apfs_result = subprocess.run(
                        ["/usr/local/bin/apfs-fuse", "-o", "allow_other",
                         ewf1_path, destination_mount],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=60
                    )
                    if apfs_result.returncode == 0:
                        mounterr = "b''"
                        mounted_fs_type = "apfs"
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    # apfs-fuse not installed or timed out
                    pass

            if mounterr != "b''":
                # All mount attempts failed - provide diagnostic information
                print(f"    ERROR: All mount attempts failed for E01 image '{disk_file}'")
                print(f"    Attempted filesystem types: NTFS (loop), HFS+ (loop), ext4 (loop), XFS (loop), ntfs-3g (FUSE), fuse2fs (ext4 FUSE), apfs-fuse")
                print(f"    This may be due to:")
                print(f"      - Unsupported or corrupted filesystem")
                print(f"      - Missing kernel modules in container")
                print(f"      - Permission issues with FUSE devices")
                # Check if ewf1 file exists
                ewf1_check_path = intermediate_mount + "/ewf1"
                if os.path.exists(ewf1_check_path):
                    try:
                        file_result = subprocess.run(["file", ewf1_check_path], capture_output=True, text=True, timeout=10)
                        print(f"    Raw disk type: {file_result.stdout.strip()}")
                    except:
                        pass
                return allimgs, partitions  # Return early since mount failed

            # Mount succeeded - identify the disk image and add to allimgs
            disk_image = identify_disk_image(
                verbosity, output_directory, disk_file, destination_mount
            )
            partition = mounted_image(
                allimgs, disk_image, destination_mount, disk_file, "0"
            )
            partitions.append(
                "{}||{}".format(
                    partition[2:-1]
                    .replace("partition", "")
                    .replace("zeroth", "00zeroth")
                    .replace("first", "01first")
                    .replace("second", "02second")
                    .replace("third", "03third")
                    .replace("forth", "04forth")
                    .replace("fifth", "05fifth")
                    .replace("sixth", "06sixth")
                    .replace("seventh", "07seventh")
                    .replace("eighth", "08eighth")
                    .replace("ninth", "09ninth")
                    .strip(),
                    disk_image,
                )
            )
            if vss:
                # Ensure parent directory exists
                if not os.path.exists("/mnt/vss/"):
                    os.makedirs("/mnt/vss/")
                os.mkdir("/mnt/vss/" + disk_file.split("::")[0] + "/")
                subprocess.Popen(
                    [
                        "vshadowmount",
                        intermediate_mount + "/ewf1",
                        "/mnt/vss/" + disk_file.split("::")[0] + "/",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
                time.sleep(0.5)
                if os.path.exists(
                    "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                ):
                    for current in os.listdir(
                        "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                    ):
                        subprocess.Popen(
                            [
                                "umount",
                                "/mnt/shadow_mount/"
                                + disk_file.split("::")[0]
                                + "/"
                                + current,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()
                        time.sleep(0.1)
                        shutil.rmtree(
                            "/mnt/shadow_mount/"
                            + disk_file.split("::")[0]
                            + "/"
                            + current
                        )
                        shutil.rmtree(
                            "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                        )
                else:
                    # Ensure parent directory exists
                    if not os.path.exists("/mnt/shadow_mount/"):
                        os.makedirs("/mnt/shadow_mount/")
                    os.mkdir("/mnt/shadow_mount/" + disk_file.split("::")[0] + "/")
                    for i in os.listdir(
                        "/mnt/vss/" + disk_file.split("::")[0] + "/"
                    ):
                        os.mkdir(
                            "/mnt/shadow_mount/"
                            + disk_file.split("::")[0]
                            + "/"
                            + i
                        )
                        try:
                            subprocess.Popen(
                                [
                                    "mount",
                                    "-o",
                                    "ro,loop,show_sys_files,streams_interface=windows",
                                    "/mnt/vss/"
                                    + disk_file.split("::")[0]
                                    + "/"
                                    + i,
                                    "/mnt/shadow_mount/"
                                    + disk_file.split("::")[0]
                                    + "/"
                                    + i,
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()
                            time.sleep(0.1)
                        except:
                            pass
                os.chdir(cwd)
            elif (
                "unknown filesystem type 'apfs'" in mounterr
                or "wrong fs type" in mounterr
            ):  # mounting images with multiple valid partitions
                if "unknown filesystem type 'apfs'" in mounterr:
                    try:
                        # Try apfs-fuse for APFS filesystems (macOS 10.13+)
                        # Path: /usr/local/bin/apfs-fuse (symlinked in Dockerfile)
                        attempt_to_mount = str(
                            subprocess.Popen(
                                [
                                    "/usr/local/bin/apfs-fuse",
                                    "-o",
                                    "allow_other",
                                    intermediate_mount + "/ewf1",
                                    destination_mount,
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()[1]
                        )
                        if attempt_to_mount == "b''":
                            if verbosity != "":
                                disk_image = identify_disk_image(
                                    verbosity,
                                    output_directory,
                                    disk_file,
                                    destination_mount,
                                )
                                partition = mounted_image(
                                    allimgs,
                                    disk_image,
                                    destination_mount,
                                    disk_file,
                                    "0",
                                )
                                partitions.append(
                                    "{}||{}".format(
                                        partition[2:-1]
                                        .replace("partition", "")
                                        .replace("zeroth", "00zeroth")
                                        .replace("first", "01first")
                                        .replace("second", "02second")
                                        .replace("third", "03third")
                                        .replace("forth", "04forth")
                                        .replace("fifth", "05fifth")
                                        .replace("sixth", "06sixth")
                                        .replace("seventh", "07seventh")
                                        .replace("eighth", "08eighth")
                                        .replace("ninth", "09ninth")
                                        .strip(),
                                        disk_image,
                                    )
                                )
                        elif "mountpoint is not empty" in attempt_to_mount:
                            pass
                    except:
                        pass
                else:  # mounting images with multiple valid partitions
                    offset_values = obtain_offset(intermediate_mount + "/ewf1")
                    if len(offset_values) > 0:
                        for offset_value in offset_values:
                            destination_mount, intermediate_mount = (
                                elrond_mount[0],
                                ewf_mount[0],
                            )
                            if not os.path.exists(intermediate_mount):
                                os.mkdir(intermediate_mount)
                            mount_ewf(path, intermediate_mount)
                            if not os.path.exists(destination_mount):
                                os.mkdir(destination_mount)
                            attempt_to_mount = str(
                                subprocess.Popen(
                                    [
                                        "mount",
                                        "-o",
                                        "ro,loop,show_sys_files,streams_interface=windows,offset="
                                        + str(int(offset_value) * 512),
                                        intermediate_mount + "/ewf1",
                                        destination_mount,
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[1]
                            )
                            if len(os.listdir(destination_mount)) > 0:
                                if (
                                    verbosity != ""
                                    and offset_values.index(offset_value) == 0
                                ):
                                    disk_image = identify_disk_image(
                                        verbosity,
                                        output_directory,
                                        disk_file,
                                        destination_mount,
                                    )
                                partition = mounted_image(
                                    allimgs,
                                    disk_image,
                                    destination_mount,
                                    disk_file,
                                    offset_values.index(offset_value),
                                )
                                partitions.append(
                                    "{}||{}".format(
                                        partition[2:-1]
                                        .replace("partition", "")
                                        .replace("zeroth", "00zeroth")
                                        .replace("first", "01first")
                                        .replace("second", "02second")
                                        .replace("third", "03third")
                                        .replace("forth", "04forth")
                                        .replace("fifth", "05fifth")
                                        .replace("sixth", "06sixth")
                                        .replace("seventh", "07seventh")
                                        .replace("eighth", "08eighth")
                                        .replace("ninth", "09ninth")
                                        .strip(),
                                        disk_image,
                                    )
                                )
                            elrond_mount.pop(0)
                            ewf_mount.pop(0)
            elif "is already mounted." in mounterr:
                pass
        elif ("VMware" in imgformat and " disk image" in imgformat) or (
            "DOS/MBR boot sector" in imgformat
            and (
                disk_file.endswith(".vmdk")
                or disk_file.endswith(".raw")
                or disk_file.endswith(".dd")
                or disk_file.endswith(".img")
            )
        ):
            if d.startswith("/"):
                (
                    destination_mount,
                    intermediate_mount,
                ) = (
                    elrond_mount[0],
                    "/" + d.strip("/") + "/" + disk_file.strip("/"),
                )
            else:
                (
                    destination_mount,
                    intermediate_mount,
                ) = (
                    elrond_mount[0],
                    d.strip("/") + "/" + disk_file.strip("/"),
                )
            if "DOS/MBR boot sector" in imgformat and disk_file.endswith(".dd"):
                partitions = mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    path,
                    allimgs,
                    partitions,
                )
            elif "DOS/MBR boot sector" in imgformat and disk_file.endswith(
                ".raw"
            ):  # vmdk file has already been converted (not using elrond)
                if auto != True:
                    vmdkow = safe_input(
                        "    '{}' has already been converted, do you wish to overwrite this file? Y/n [Y] ".format(
                            intermediate_mount.split("/")[-1]
                        ),
                        default="n"
                    )
                else:
                    vmdkow = "n"
                if vmdkow != "n" or "Invalid partition table" in imgformat:
                    if "Invalid partition table" in imgformat:
                        print(
                            "    It looks like '{}' is corrupt; it will be removed and will need to be re-converted, please try again.".format(
                                intermediate_mount.split("/")[-1]
                            )
                        )
                        # insert Continue? here...
                partitions = mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    path,
                    allimgs,
                    partitions,
                )
            else:  # raw vmdk file can be mounted
                partitions = mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    path,
                    allimgs,
                    partitions,
                )
        elif imgformat.strip() == "data" and (
            disk_file.endswith(".raw")
            or disk_file.endswith(".img")
            or disk_file.endswith(".dd")
        ):
            # Handle raw filesystem images (no partition table) - common for macOS HFS+/APFS
            # These show as "data" from `file` command since they're raw filesystem dumps
            print(f"  -> Detected raw filesystem image (no partition table): {disk_file}")
            destination_mount = elrond_mount[0]

            # Try APFS first (macOS 10.13+)
            try:
                apfs_result = subprocess.run(
                    ["/usr/local/bin/apfs-fuse", "-o", "allow_other", path, destination_mount],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60
                )
                if apfs_result.returncode == 0 and os.listdir(destination_mount):
                    print(f"  -> Successfully mounted {disk_file} as APFS")
                    disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                    partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, "0")
                    partitions.append(f"{partition[2:-1].strip()}||{disk_image}")
                else:
                    raise Exception("APFS mount failed")
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                # Try HFS+ (older macOS)
                try:
                    hfs_result = subprocess.run(
                        ["mount", "-t", "hfsplus", "-o", "ro,loop", path, destination_mount],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30
                    )
                    if hfs_result.returncode == 0 and os.listdir(destination_mount):
                        print(f"  -> Successfully mounted {disk_file} as HFS+")
                        disk_image = identify_disk_image(verbosity, output_directory, disk_file, destination_mount)
                        partition = mounted_image(allimgs, disk_image, destination_mount, disk_file, "0")
                        partitions.append(f"{partition[2:-1].strip()}||{disk_image}")
                    else:
                        raise Exception("HFS+ mount failed")
                except Exception:
                    # Try kpartx fallback (may be a partitioned image misidentified by `file`)
                    if _mount_with_kpartx(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
                        pass  # Successfully mounted via kpartx
                    else:
                        # Try guestmount as final fallback
                        if not _try_guestmount(path, destination_mount, disk_file, allimgs, partitions, verbosity, output_directory):
                            print(f"   ERROR: '{disk_file}' could not be mounted.")
                            print(f"   This appears to be a raw filesystem image but no compatible filesystem was found.")
                            print(f"   For macOS HFS+ images in Docker, the kernel module may not be available.")
                            print(f"   Consider using a native Linux host with hfsplus kernel module loaded.")
        # Log to audit file but don't print "commenced" - it's superfluous output
        entry = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), disk_file, stage
        )
        write_audit_log_entry(verbosity, output_directory, entry, "")
    return allimgs, partitions
