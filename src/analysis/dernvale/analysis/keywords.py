#!/usr/bin/env python3 -tt
import os
import re
import time
from datetime import datetime

from dernvale.audit import write_audit_log_entry
from dernvale.utils import safe_input

_WRITE_FAILED = set()


def write_keywords(
    output_directory,
    verbosity,
    img,
    vssimage,
    keyword_search_file,
    keywords_target_file,
    eachkeyword,
    encoding_choice,
    vsstext,
):
    keyword_line_number = 1
    for eachline in keyword_search_file:
        if eachkeyword.lower().strip() in eachline.lower().strip():
            (
                entry,
                prnt,
            ) = "{},{},keyword identified,{} (line {}) found in {}\n".format(
                datetime.now().isoformat(),
                vssimage,
                eachkeyword.strip(),
                keyword_line_number,
                keywords_target_file.split("/")[-1],
            ), " -> {} -> identified keyword '{}' on line {} in '{}' from {}{}".format(
                datetime.now().isoformat().replace("T", " "),
                eachkeyword.strip(),
                keyword_line_number,
                keywords_target_file.split("/")[-1],
                vssimage,
                vsstext,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            keyword_match_entry = "{},{},{},{},{},{},{}\n".format(
                str(
                    datetime.fromtimestamp(
                        os.path.getctime(keywords_target_file.split(": ")[0])
                    )
                ),
                str(
                    datetime.fromtimestamp(
                        os.path.getatime(keywords_target_file.split(": ")[0])
                    )
                ),
                str(
                    datetime.fromtimestamp(
                        os.path.getmtime(keywords_target_file.split(": ")[0])
                    )
                ),
                eachkeyword.strip(),
                keywords_target_file.replace(",", "%2C"),
                str(keyword_line_number),
                eachline.strip().replace(",", "%2C").replace("\n", "\\n"),
            )
            kw_match_entry = (
                str(keyword_match_entry.split())[2:-2]
                .replace("', '", " ")
                .replace("\\x", "\\\\x")
                .replace("\\\\\\", "\\\\")
            )
            if len(keyword_match_entry.split(",")[-1]) > 200:
                kw_match_entry = (
                    ",".join(keyword_match_entry.split(",")[0:-1])
                    + ","
                    + keyword_match_entry.split(",")[-1][0:200]
                    + "<>TRUNCATED<>\n"
                )
            else:
                kw_match_entry = kw_match_entry + "\n"
            matches = output_directory + img.split("::")[0] + "/analysis/keyword_matches.csv"
            try:
                with open(matches, "a", encoding=encoding_choice) as keyword_matches_results_file:
                    keyword_matches_results_file.write(kw_match_entry)
            except OSError as e:
                # endpoint AV on the analysis machine can delete or lock the CSV (it
                # quotes the matched lines); one lost write mustn't end the host's analysis
                if matches not in _WRITE_FAILED:
                    _WRITE_FAILED.add(matches)
                    print(" -> {} -> warning: could not write '{}': {}".format(
                        datetime.now().isoformat().replace("T", " "), matches, e))
        keyword_line_number += 1


def search_keywords(
    verbosity,
    output_directory,
    img,
    keywords,
    keywords_target_list,
    vssimage,
    insert,
    vsstext,
):
    analysis_dir = output_directory + img.split("::")[0] + "/analysis/"
    os.makedirs(analysis_dir, exist_ok=True)
    # Header whenever the CSV is new, not only when analysis/ didn't exist yet.
    if not os.path.exists(analysis_dir + "keyword_matches.csv"):
        with open(
            output_directory + img.split("::")[0] + "/analysis/keyword_matches.csv",
            "a",
        ) as keyword_matches_results_file:
            keyword_matches_results_file.write(
                "CreationTime,LastAccessTime,LastWriteTime,keyword,Filename,line_number,line_entry\n"
            )
    with open(keywords[0], "r") as keywords_source_file:
        # A blank line is "" after strip(), which is "in" every line, so one empty
        # line in the list matched everything (45 min -> 14.6 h). Skip blanks and
        # comments.
        search_terms = [
            k for k in keywords_source_file if k.strip() and not k.lstrip().startswith("#")
        ]
        for eachkeyword in search_terms:
            for keywords_target_file in keywords_target_list:
                try:
                    encoding_choice = "UTF-8"
                    with open(
                        keywords_target_file, "r", encoding=encoding_choice
                    ) as keyword_search_file:
                        write_keywords(
                            output_directory,
                            verbosity,
                            img,
                            vssimage,
                            keyword_search_file,
                            keywords_target_file,
                            eachkeyword,
                            encoding_choice,
                            vsstext,
                        )
                except:
                    encoding_choice = "ISO-8859-1"
                    with open(
                        keywords_target_file, "r", encoding=encoding_choice
                    ) as keyword_search_file:
                        write_keywords(
                            output_directory,
                            verbosity,
                            img,
                            vssimage,
                            keyword_search_file,
                            keywords_target_file,
                            eachkeyword,
                            encoding_choice,
                            vsstext,
                        )


def build_keyword_list(mnt):
    keywords_target_list = []
    for keyword_search_root, _, keyword_search_file in os.walk(mnt):
        for keyword_search_file in keyword_search_file:
            try:
                if (
                    os.stat(
                        os.path.join(keyword_search_root, keyword_search_file)
                    ).st_size
                    > 0
                    and os.stat(
                        os.path.join(keyword_search_root, keyword_search_file)
                    ).st_size
                    < 100000000
                    and not os.path.islink(
                        os.path.join(keyword_search_root, keyword_search_file)
                    )  # 100MB
                ):
                    with open(
                        os.path.join(keyword_search_root, keyword_search_file), "r"
                    ) as filetest:
                        filetest.readline()
                        keywords_target_list.append(
                            os.path.join(keyword_search_root, keyword_search_file)
                        )
            except:
                pass
            try:
                if (
                    os.stat(
                        os.path.join(keyword_search_root, keyword_search_file)
                    ).st_size
                    > 0
                    and os.stat(
                        os.path.join(keyword_search_root, keyword_search_file)
                    ).st_size
                    < 100000000
                    and not os.path.islink(
                        os.path.join(keyword_search_root, keyword_search_file)
                    )  # 100MB
                ):
                    with open(
                        os.path.join(keyword_search_root, keyword_search_file),
                        "r",
                        encoding="ISO-8859-1",
                    ) as filetest:
                        filetest.readline()
                        keywords_target_list.append(
                            os.path.join(keyword_search_root, keyword_search_file)
                        )
            except:
                pass
    return keywords_target_list


def prepare_keywords(verbosity, output_directory, auto, imgs, flags, keywords, stage):
    # Check if we're in the mounting/metadata phase (when filesystem is still mounted)
    # Stage can be "mounting" or "metadata" at this point
    if stage in ("mounting", "metadata"):
        if not auto:
            yes_kw = safe_input("  Do you wish to conduct Keyword Searching for '{}'? Y/n [Y] ".format(
                    img.split("::")[0]
                )
            )
        if auto or yes_kw != "n":
            print(
                "\n\n  -> \033[1;36mCommencing Keyword Searching Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            for mnt, img in imgs.items():
                stage = "keyword searching"
                if "vss" in img.split("::")[1]:
                    vssimage, vsstext = (
                        "'"
                        + img.split("::")[0]
                        + "' ("
                        + img.split("::")[1]
                        .split("_")[1]
                        .replace("vss", "volume shadow copy #")
                        + ")",
                        " ("
                        + img.split("::")[1]
                        .split("_")[1]
                        .replace("vss", "volume shadow copy #")
                        + ")",
                    )
                else:
                    vssimage, vsstext = "'" + img.split("::")[0] + "'", ""
                print("    Conducting Keyword Searching for {}...".format(vssimage))
                entry, prnt = "{},{},{},commenced\n".format(
                    datetime.now().isoformat(), vssimage.replace("'", ""), stage
                ), " -> {} -> {} commenced for '{}'{}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    img.split("::")[0],
                    vsstext,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                print(
                    "     Assessing readable files in {} before searching for keywords...".format(
                        vssimage
                    )
                )
                keywords_target_list = build_keyword_list(mnt)

                search_keywords(
                    verbosity,
                    output_directory,
                    img,
                    keywords,
                    keywords_target_list,
                    vssimage,
                    vssimage,
                    vsstext,
                )
                print("  -> Completed Keyword Searching Phase for {}".format(vssimage))
                entry, prnt = "{},{},{},completed\n".format(
                    datetime.now().isoformat(),
                    vssimage.replace("'", ""),
                    "keyword searching",
                ), " -> {} -> keyword searching completed for {}".format(
                    datetime.now().isoformat().replace("T", " "), vssimage
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                print()
            print(
                "  ----------------------------------------\n  -> Completed Keyword Searching Phase.\n"
            )
            time.sleep(1)
    else:
        # imgs maps mount point -> "host::type"; the host is what names the output
        for each in imgs.values():
            vsstext = ""  # Initialize vsstext for non-mounting stage
            if os.path.exists(
                os.path.join(output_directory, each.split("::")[0], "artefacts")
            ):
                mnt = os.path.join(output_directory, each.split("::")[0], "artefacts")
                keywords_target_list = build_keyword_list(mnt)
                search_keywords(
                    verbosity,
                    output_directory,
                    each.split("::")[0],
                    keywords,
                    keywords_target_list,
                    each.split("::")[0],
                    "collected/processed artefacts",
                    vsstext,
                )
            if os.path.exists(
                os.path.join(output_directory, each.split("::")[0], "files")
            ):  # for office documents and archives - extract and then build keyword search list
                mnt = os.path.join(output_directory, each.split("::")[0], "files")
                keywords_target_list = build_keyword_list(mnt)
                search_keywords(
                    verbosity,
                    output_directory,
                    each.split("::")[0],
                    keywords,
                    keywords_target_list,
                    each.split("::")[0],
                    "collected files",
                    vsstext,
                )
    if "keyword searching" not in str(flags):
        flags.append("03keyword searching")
