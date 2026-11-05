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


quotes = [
    "     Now come the days of the King, and may they be blessed.\n     -- Gandalf, The Return of the King\n",
    "     Forty-two, Master Legolas!\n     -- Gimli, The Two Towers\n",
    "     There is a lot more in him than you guess,\n     and a deal more than he has any idea of himself.\n     -- Gandalf, The Hobbit\n",
    "     One Ring to rule them all, One Ring to find them,\n     One Ring to bring them all and in the darkness bind them.\n     -- the Ring-verse, The Fellowship of the Ring\n",
    "     The world is changing: I feel it in the water,\n     I feel it in the earth, and I smell it in the air.\n     -- Treebeard, The Return of the King\n",
    "     Who knows? Have patience. Go where you must go, and hope!\n     -- Gandalf, The Two Towers\n",
    "     All we have to decide is what to do with the time that is given us.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Deeds will not be less valiant because they are unpraised.\n     -- Aragorn, The Two Towers\n",
    "     In the end the Shadow was only a small and passing thing.\n     -- Sam, in Mordor, The Return of the King\n",
    "     It's the job that's never started as takes longest to finish.\n     -- Sam, after the Gaffer, The Fellowship of the Ring\n",
    "     I laid low the warriors of old and their like is not in the world today.\n     -- Smaug, The Hobbit\n",
    "     Something is the matter with you! You are not the hobbit that you were.\n     -- Gandalf, The Hobbit\n",
    "     Do not be too eager to deal out death in judgement.\n     For even the very wise cannot see all ends.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     The treacherous are ever distrustful.\n     -- Gandalf, The Two Towers\n",
    "     Let him not vow to walk in the dark, who has not seen the nightfall.\n     -- Elrond, The Fellowship of the Ring\n",
    "     He that breaks a thing to find out what it is has left the path of wisdom.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     I was the herald of Gil-galad and marched with his host.\n     -- Elrond, The Fellowship of the Ring\n",
    "     I don't know half of you half as well as I should like;\n     and I like less than half of you half as well as you deserve.\n     -- Bilbo, The Fellowship of the Ring\n",
    "     The Company of the Ring shall be Nine;\n     and the Nine Walkers shall be set against the Nine Riders that are evil.\n     -- Elrond, The Fellowship of the Ring\n",
    "     You shall not pass!\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Keep it secret, and keep it safe!\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Small hands do them because they must, while the eyes of the great are elsewhere.\n     -- Elrond, The Fellowship of the Ring\n",
    "     I wish it need not have happened in my time.\n     -- Frodo, The Fellowship of the Ring\n",
    "     A hunted man sometimes wearies of distrust and longs for friendship.\n     -- Aragorn, The Fellowship of the Ring\n",
    "     The world is indeed full of peril, and in it there are many dark places.\n     -- Haldir, The Fellowship of the Ring\n",
    "     Someone else always has to carry on the story.\n     -- Bilbo, The Fellowship of the Ring\n",
    "     It is useless to meet revenge with revenge: it will heal nothing.\n     -- Frodo, The Return of the King\n",
    "     Despair is only for those who see the end beyond all doubt. We do not.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Speak, friend, and enter.\n     -- the West-gate of Moria, The Fellowship of the Ring\n",
    "     The wise speak only of what they know.\n     -- Gandalf, The Two Towers\n",
    "     Not all those who wander are lost.\n     -- Bilbo's verse, The Fellowship of the Ring\n",
    "     It's the deep breath before the plunge.\n     -- Gandalf, The Return of the King\n",
    "     There is nothing like looking, if you want to find something.\n     -- Thorin, The Hobbit\n",
    "     You certainly usually find something, if you look,\n     but it is not always quite the something you were after.\n     -- the narrator, The Hobbit\n",
    "     It does not do to leave a live dragon out of your calculations, if you live near him.\n     -- the narrator, The Hobbit\n",
    "     Never laugh at live dragons, Bilbo you fool!\n     -- Bilbo, The Hobbit\n",
    "     What has it got in its pocketses?\n     -- Gollum, The Hobbit\n",
    "     Thief, thief, thief! Baggins!\n     -- Gollum, The Hobbit\n",
    "     I am looking for someone to share in an adventure that I am arranging,\n     and it's very difficult to find anyone.\n     -- Gandalf, The Hobbit\n",
    "     We are plain quiet folk and have no use for adventures.\n     -- Bilbo, The Hobbit\n",
    "     In a hole in the ground there lived a hobbit.\n     -- the opening line, The Hobbit\n",
    "     Escaping goblins to be caught by wolves!\n     -- Bilbo, The Hobbit\n",
    "     Where there's life there's hope.\n     -- Bilbo, The Hobbit\n",
    "     Short cuts make long delays.\n     -- Pippin, The Fellowship of the Ring\n",
    "     It's a dangerous business, Frodo, going out your door.\n     -- Bilbo, The Fellowship of the Ring\n",
    "     The Road goes ever on and on\n     Down from the door where it began.\n     -- Bilbo's walking-song, The Fellowship of the Ring\n",
    "     Advice is a dangerous gift, even from the wise to the wise,\n     and all courses may run ill.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     It is perilous to study too deeply the arts of the Enemy, for good or for ill.\n     -- Elrond, The Fellowship of the Ring\n",
    "     Always after a defeat and a respite, the Shadow takes another shape and grows again.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Faithless is he that says farewell when the road darkens.\n     -- Gimli, The Fellowship of the Ring\n",
    "     Do not meddle in the affairs of Wizards, for they are subtle and quick to anger.\n     -- Gildor, The Fellowship of the Ring\n",
    "     Go not to the Elves for counsel, for they will say both no and yes.\n     -- Frodo, The Fellowship of the Ring\n",
    "     Not idly do the leaves of Lorien fall.\n     -- Aragorn, The Two Towers\n",
    "     Strange are the turns of fortune! Often does hatred hurt itself!\n     -- Gandalf, The Two Towers\n",
    "     The burned hand teaches best.\n     After that advice about fire goes to the heart.\n     -- Gandalf, The Two Towers\n",
    "     Oft hope is born when all is forlorn.\n     -- Legolas, The Return of the King\n",
    "     Fly, you fools!\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Well, I'm back.\n     -- Sam, The Return of the King\n",
    "     This tale grew in the telling.\n     -- Tolkien's foreword, The Fellowship of the Ring\n",
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
         \033[1;35m____                      .___        .__    _____  
        / ___\ _____     ____    __| _/\033[4mECRYPT\033[0;m\033[1;35m  |  | _/ ____\ 
       / /_/  >\__  \   /    \  / __ | \__  \  |  | \   __\  
       \___  /  / __ \_|   |  \/ /_/ |  / __ \_|  |__|  |    
      /_____/  (____  /|___|  /\____ | (____  /|____/|__|    
                    \/      \/      \/      \/               \n\n{}\033[1;m
    """.format(
            random.choice(quotes)
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
