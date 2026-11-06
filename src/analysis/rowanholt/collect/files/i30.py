#!/usr/bin/env python3 -tt
import os
import shutil
import subprocess
from datetime import datetime

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, read_records, write_records
from rowanholt.mount import obtain_offset


def rip_i30(output_directory, img, offset):
    """INDXRipper's I30 entries for one partition, as artefacts/I30_<offset>.jsonl (it writes CSV)."""
    table = output_directory + img.split("::")[0] + "/" + "artefacts/I30_" + offset
    if not os.path.exists(table + SUFFIX):
        indxripper_result = subprocess.Popen(
            [
                "sudo",
                "python3.9",
                "/opt/elrond/elrond/tools/INDXRipper/INDXRipper.py",
                "-w",
                "csv",
                "-o",
                "{}".format(offset),
                "/mnt/i30_{}/ewf1".format(img.split("::")[0]),
                output_directory
                + img.split("::")[0]
                + "/"
                + "artefacts/I30_"
                + offset
                + ".csv",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        if os.path.exists(table + ".csv"):
            write_records(table + SUFFIX, (r for _, r in read_records(table + ".csv")),
                          host=img.split("::")[0], artefact="I30_" + offset, source_path=img.split("::")[0],
                          time_field=("LastModified", "Modified", "Created"))
            os.remove(table + ".csv")
    else:
        indxripper_result = ["", ""]
    return indxripper_result


def extract_i30(
    output_directory,
    verbosity,
    stage,
    d,
    img,
    vssimage,
):
    if ("Windows" in img.split("::")[1] and "memory_" not in img.split("::")[1]) and (
        "I30_"
        not in str(
            os.listdir(output_directory + img.split("::")[0] + "/" + "artefacts")
        )
    ):
        # Stop once the image is handled: d is the evidence directory and may hold
        # large output trees (e.g. a case output under the image folder).
        i30_done = False
        for image_root, _, image_files in os.walk(d):
            for image_file in image_files:
                if (
                    image_file.endswith(".E01") or image_file.endswith(".e01")
                ) and img.split("::")[0] in image_file:
                    i30_source = os.path.join(image_root, image_file)
                    if os.path.exists("/mnt/i30_{}".format(img.split("::")[0])):
                        subprocess.Popen(
                            ["umount", "/mnt/i30_{}".format(img.split("::")[0])],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()
                        shutil.rmtree("/mnt/i30_{}".format(img.split("::")[0]))
                    os.mkdir("/mnt/i30_{}".format(img.split("::")[0]))
                    os.chmod("/mnt/i30_{}".format(img.split("::")[0]), 0o0777)
                    if img.split("::")[0].endswith(".E01") or img.split("::")[
                        0
                    ].endswith(".e01"):
                        subprocess.Popen(
                            [
                                "ewfmount",
                                i30_source,
                                "/mnt/i30_{}".format(img.split("::")[0]),
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()
                        subprocess.Popen(
                            [
                                "chmod",
                                "-f",
                                "777",
                                "/mnt/i30_{}".format(img.split("::")[0]),
                            ]
                        ).communicate()
                        subprocess.Popen(
                            [
                                "chmod",
                                "-f",
                                "777",
                                "/mnt/i30_{}/ewf1".format(img.split("::")[0]),
                            ]
                        ).communicate()
                        indxripper_result = rip_i30(output_directory, img, "0")
                        if (
                            "invalid volume boot record"
                            in str(indxripper_result[1])[2:-3]
                        ):
                            offset_values = obtain_offset(
                                "/mnt/i30_{}/ewf1".format(img.split("::")[0])
                            )
                            for eachoffset in offset_values:
                                indxripper_result = rip_i30(
                                    output_directory, img, str(eachoffset)
                                )
                                if str(indxripper_result[1]) != "b''":
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},recovery,$I30 records (failed)\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                    ), "  -> {} -> recovery of $I30 records failed from {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity, output_directory, entry, prnt
                                    )
                                elif str(indxripper_result[1]) == "b''":
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},$I30 records (#{})\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        stage,
                                        eachoffset,
                                    ), "  -> {} -> {} $I30 records (#{}) from {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        stage,
                                        eachoffset,
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity, output_directory, entry, prnt
                                    )
                        else:
                            entry, prnt = "{},{},{},$I30 records\n".format(
                                datetime.now().isoformat(),
                                vssimage.replace("'", ""),
                                stage,
                            ), " -> {} -> {} $I30 records from {}".format(
                                datetime.now().isoformat().replace("T", " "),
                                stage,
                                vssimage,
                            )
                            write_audit_log_entry(
                                verbosity, output_directory, entry, prnt
                            )
                    subprocess.Popen(
                        ["umount", "/mnt/i30_{}".format(img.split("::")[0])],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()
                    shutil.rmtree("/mnt/i30_{}".format(img.split("::")[0]))
                    i30_done = True
            if i30_done:
                break
