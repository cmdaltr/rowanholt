#!/usr/bin/env python3 -tt
import base64
import getpass
import os
import random
import subprocess
import sys
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# A copy of QUIPS in src/common/quips.py, the source: this script runs on its own, without the
# rest of the repo, so the copy must match it
quotes = [
    "Hash it before you trust it.",
    "Volatile first. The disk will wait; the RAM won't.",
    "If it isn't in the timeline, it didn't happen. If it is, prove it.",
    "Every artefact is innocent until correlated.",
    "The attacker cleared the logs. The logs about the logs are still here.",
    "Absence of evidence is a finding. Write it down.",
    "Time zones: the oldest adversary.",
    "Never analyse the original. Not even once. Especially not once.",
    "Prefetch remembers what the user would rather forget.",
    "The registry keeps secrets badly and grudges well.",
    "A clean system is either clean or very well cleaned.",
    "Your hypothesis is not your conclusion. Yet.",
    "Write the report as if the defence will read it. They will.",
    "Chain of custody: boring until the day it isn't.",
    "Correlation is a lead. Causation needs a second source.",
    "Timestamps lie. Four of them lie less.",
    "The first alert is rarely the first event.",
    "Living off the land still leaves footprints in the mud.",
    "Assume the clock is wrong until it proves otherwise.",
    "Scope creep is also an incident.",
    "Read the ShimCache, then distrust it accordingly.",
    "If the binary is signed, ask who signed it and why.",
    "Every persistence mechanism was somebody's convenience feature.",
    "The quietest host is worth a second look.",
    "Collect broadly. Conclude narrowly.",
    "No IOC survives contact with a competent adversary.",
    "Lateral movement leaves logons. Logons leave 4624s.",
    "Deleted is a state of mind. The MFT disagrees.",
    "Document now. Your memory is not evidence.",
    "The answer is in the data. The question is usually the problem.",
]


def generate_passkey():
    pswd = getpass.getpass(
        "    \033[1;30mEnter password to decrypt acquisition archive:\033[1;m "
    ).encode()
    password = bytes(pswd)
    pswdsalt = input(
        "    \033[1;30mEnter salt [isengard.pork]:\033[1;m "
    ) or "isengard.pork"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=bytes(pswdsalt.encode()), 
        iterations=480000,
    ) 
    key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher = Fernet(key)
    return cipher


def main():
    subprocess.Popen(["clear"])
    time.sleep(2)
    print(
        """
    \n\n
      \033[1;35m                       __             .___.__
        ____  __ __  _______/  |_  ____   __| _/|__|____    ____
      _/ ___\\|  |  \\/  ___/\\   __\\/  _ \\ / __ | |  \\__  \\  /    \\
      \\  \\___|  |  /\\___ \\  |  | (  <_> ) /_/ | |  |/ __ \\|   |  \\
       \\___  >____//____  > |__|  \\____/\\____ | |__(____  /___|  /
           \\/           \\/                   \\/         \\/     \\/
                                                   \033[4mDECRYPT\033[0;m\033[1;35m\n\n{}\033[1;m
    """.format(
            "     " + random.choice(quotes) + "\n"
        )
    )
    encrypted_archive = input(
        "    Provide location of encrypted archive: "
    )
    print()
    if not encrypted_archive.endswith(".zip.enc"):
        print("    {} must end with '.zip.enc', please try again.\n\n".format(encrypted_archive))
        sys.exit()
    elif not os.path.exists(encrypted_archive):
        print("    {} does not exist, please try again.\n\n".format(encrypted_archive))
        sys.exit()
    elif not os.path.isfile(encrypted_archive):
        print("    {} is not of file 'type', please try again.\n\n".format(encrypted_archive))
        sys.exit()
    else:
        cipher = generate_passkey()
        with open(encrypted_archive, "rb") as enc_archive:
            encrypted_content = enc_archive.read()
        decrypted_content = cipher.decrypt(encrypted_content)
        with open("{}.dec.zip".format(encrypted_archive[0:-8]), "wb") as dec_archive:
            dec_archive.write(decrypted_content)
        print("\n    Successfully decrypted \033[1;30m{}\033[1;m\n                        to \033[1;32m{}.dec.zip\033[1;m\n\n".format(encrypted_archive, encrypted_archive[0:-8]))


if __name__ == "__main__":
    main()
