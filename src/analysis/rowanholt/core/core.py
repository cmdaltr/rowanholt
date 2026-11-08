import os
import shutil
import sys
import time
from datetime import datetime

from rowanholt.analysis.analysis import analyse_artefacts
from rowanholt.analysis.keywords import prepare_keywords
from rowanholt.audit import write_audit_log_entry
from rowanholt.collect.collect import collect_artefacts
from rowanholt.core.identify import process_deferred_memory, load_memory_profiles
from rowanholt.core.mobile import is_mobile_image
from rowanholt.process.mobile import process_mobile
# Reorganise functionality removed - redundant
from rowanholt.process.select import select_pre_process_artefacts
from rowanholt.process.timeline import convert_plaso_timeline, create_plaso_timeline
from rowanholt.utils import safe_input, safe_listdir, safe_iterdir


def collect_process_keyword_analysis_timeline(
    auto,
    collect,
    process,
    analysis,
    magicbytes,
    extractiocs,
    iocsfile,
    timeline,
    vss,
    collectfiles,
    nsrl,
    keywords,
    volatility,
    metacollected,
    symlinks,
    userprofiles,
    verbose,
    d,
    cwd,
    sha256,
    flags,
    system_artefacts,
    output_directory,
    verbosity,
    f,
    allimgs,
    imgs,
    path,
    volchoice,
    vssmem,
    memtimeline,
    stage,
    phase=None,  # Phase control: "collect", "process", or None for full pipeline
):
    # PHASE CONTROL: Skip collection if in "process" or "analyse" phase
    if collect and len(imgs) != 0 and phase not in ("process", "analyse"):
        collect_artefacts(
            auto,
            vss,
            collectfiles,
            nsrl,
            keywords,
            volatility,
            metacollected,
            symlinks,
            userprofiles,
            verbose,
            d,
            cwd,
            sha256,
            flags,
            system_artefacts,
            output_directory,
            verbosity,
            f,
            imgs,
            path,
            volchoice,
            vssmem,
            memtimeline,
            stage,
            phase,  # Pass phase to control output messages
        )
        # Use safe_iterdir for macOS Docker VirtioFS filesystem compatibility
        for entry in safe_iterdir(output_directory):
            eachdir = entry.name
            if entry.is_dir() and eachdir != ".DS_Store":
                if len(safe_listdir(entry.path)) == 0:
                    os.rmdir(entry.path)

        # PHASE CONTROL: If collect-only phase, return after collection
        if phase == "collect":
            return

    # PHASE CONTROL: Skip processing if in "collect" or "analyse" phase
    if phase in ("collect", "analyse"):
        pass  # Fall through to analysis section for "analyse" phase
    elif process:
        # Phones (--Mobile) branch off here: iLEAPP/ALEAPP over the evidence, not raw/'s walk
        phones = {k: v for k, v in imgs.items() if is_mobile_image(v)}
        if phones:
            process_mobile(verbosity, output_directory, phones, "processing")
        others = {k: v for k, v in imgs.items() if k not in phones}
        if others or not phones:
            select_pre_process_artefacts(
                output_directory,
                verbosity,
                d,
                flags,
                stage,
                cwd,
                others,
                f,
                path,
                vssmem,
                volatility,
                volchoice,
                vss,
                memtimeline,
                collectfiles,
            )
        # NOTE: Deferred memory processing is now handled by elrond.py after all disk images
        # are processed. This ensures proper ordering of messages and separation of phases.
        if os.path.exists("/opt/elrond/elrond/tools/.profiles"):
            os.remove("/opt/elrond/elrond/tools/.profiles")

    # PHASE CONTROL: If process-only phase, return after processing
    if phase == "process":
        return

    # PHASE CONTROL: Skip analysis/keyword search if in collect or process phase
    if phase in ("collect", "process"):
        return

    if keywords:
        if not os.path.exists(keywords[0]):
            continue_with_kw = safe_input("\n    {} is an invalid path because it does not exist. Continue? Y/n [Y] \n".format(
                    keywords[0]
                )
            )
            if continue_with_kw == "n":
                sys.exit()
        else:
            print(
                "\n\n  -> \033[1;36mCommencing Keyword Searching phase for proccessed artefacts...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            prepare_keywords(
                verbosity,
                output_directory,
                auto,
                imgs,
                flags,
                keywords,
                "keyword searching",
            )
            print(
                "  ----------------------------------------\n  -> Completed Keyword Searching phase for proccessed artefacts.\n"
            )
            time.sleep(1)
    if analysis or extractiocs:
        alysdirs = []
        analysis_errors = []  # Track any errors during analysis
        # Use safe_iterdir for macOS Docker VirtioFS filesystem compatibility
        for entry in safe_iterdir(output_directory):
            eachdir = entry.name
            if os.path.exists(output_directory + eachdir + "/artefacts"):
                alysdirs.append(output_directory + eachdir + "/artefacts")
        if len(alysdirs) > 0:
            print(
                "\n\n  -> \033[1;36mCommencing Analysis Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            for mnt, img in imgs.items():
                try:
                    # Parse image info - handle both "image::type" and plain "image" formats
                    img_parts = img.split("::")
                    img_name = img_parts[0]
                    img_type = img_parts[1] if len(img_parts) > 1 else ""

                    if "vss" in img_type:
                        vssimage = (
                            "'"
                            + img_name
                            + "' ("
                            + img_type
                            .split("_")[1]
                            .replace("vss", "volume shadow copy #")
                            + ")"
                        )
                    else:
                        vssimage = "'" + img_name + "'"

                    print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> analysing artefacts for {vssimage}...", flush=True)

                    analyse_artefacts(
                        verbosity,
                        output_directory,
                        img,
                        mnt,
                        analysis,
                        magicbytes,
                        extractiocs,
                        iocsfile,
                        vssimage,
                    )

                    print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> completed analysis for {vssimage}", flush=True)
                except Exception as e:
                    import traceback
                    # Use img_name if available, otherwise use raw img
                    image_desc = vssimage if 'vssimage' in dir() else img
                    error_msg = f"Error analysing {image_desc}: {str(e)}"
                    analysis_errors.append(error_msg)
                    print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> ERROR: {error_msg}", flush=True)
                    print(f"    Traceback: {traceback.format_exc()}", flush=True)
                    # Continue processing other images
        else:
            print(
                "  -> Analysis could not be conducted as there are no artefacts processed (-P), please try again.\n"
            )
        flags.append("04analysis")
        if analysis_errors:
            print(f"  -> WARNING: {len(analysis_errors)} error(s) occurred during analysis:")
            for err in analysis_errors:
                print(f"     - {err}")
        print(
            "  ----------------------------------------\n  -> Completed Analysis Phase.\n"
        )
        time.sleep(1)
    if timeline:
        stage = "timeline"
        # Build dict mapping image names to full img strings (name::platform)
        timeline_imgs = {}
        print(
            "\n\n  -> \033[1;36mCommencing Timeline Phase...\033[1;m\n  ----------------------------------------"
        )
        time.sleep(1)
        for _, img in imgs.items():  # Identifying images for timelining
            # Check image type (index 2) not mount point (index 1)
            img_type = img.split("::")[2] if len(img.split("::")) > 2 else ""
            if img_type != "memory":
                img_name = img.split("::")[0]
                timeline_imgs[img_name] = img
        if len(timeline_imgs) > 0:
            # Create artefacts directories for all timeline images
            for img_name in timeline_imgs:
                artefacts_dir = os.path.join(output_directory, img_name, "artefacts")
                if not os.path.exists(artefacts_dir):
                    os.makedirs(artefacts_dir)
            for timelineimage, img in timeline_imgs.items():
                timelineexist = safe_input("   Does a timeline already exist for '{}'? Y/n [n] ".format(
                        timelineimage
                    )
                )
                if timelineexist != "Y":
                    create_plaso_timeline(
                        verbosity, output_directory, stage, img, d, timelineimage
                    )
                else:

                    def doTimelineFile(timelinepath):
                        if not os.path.exists(timelinepath):
                            timelinepath = safe_input("    '{}' does not exist and/or is an invalid csv file.\n     Please provide a valid file path: ".format(
                                    timelinepath
                                )
                            )
                            doTimelineFile(timelinepath)
                        return timelinepath

                    timelinepath = safe_input("    Please provide the full file path of the timeline: "
                    )
                    timelinefile = doTimelineFile(timelinepath)
                    with open(timelinefile) as tlf:
                        firstline = tlf.readline()
                    if firstline.lstrip().startswith("{"):  # psteal's json_line output
                        convert_plaso_timeline(verbosity, output_directory, stage, img, timelinefile)
                    else:  # a CSV timeline, read as it is
                        shutil.copy2(
                            timelinefile,
                            output_directory
                            + timelineimage
                            + "/artefacts/plaso_timeline.csv",
                        )
                print(" -> Completed Timeline Phase for '{}'.".format(timelineimage))
                entry, prnt = "{},{},{},{}\n".format(
                    datetime.now().isoformat(), timelineimage, stage, timelineimage
                ), " -> {} -> {} completed for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    timelineimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                print()
            flags.append("05timelining")
            print(
                "  ----------------------------------------\n  -> Completed Timelining Phase.\n"
            )
            time.sleep(1)
