import hashlib

# Gets all salts and passwords from text file
salts = open("known-salts.txt", "r").readlines()
pws = open("top-10000-passwords.txt", "r").readlines()


def sha1(pw, salt=""):
    """
    Generates a SHA-1 hash for passwords
    Based on: https://github.com/letientai299/freecodecamp/blob/master/infosec/pwcracker/password_cracker.py#L6

    Args:
        pw (str):                Represents the plain text password
        salt (str, optional):    Represents the salt. Defaults to "".

    Returns:
        str:    Returns a SHA-1 hash
    """
    pw = pw.strip()
    if salt:
        salt = salt.strip()
        pw += salt

    return hashlib.sha1(str(pw).encode("utf-8")).hexdigest()


# Creates a dictionary of hashes
hashes = {sha1(pw): pw.strip() for pw in pws}

# Creates a dictionary of salted hashes
salted_hashes = {}
for s in salts:
    for pw in pws:
        hash1 = sha1(pw, s)
        salted_hashes[hash1] = pw.strip()
        hash2 = sha1(s, pw)
        salted_hashes[hash2] = pw.strip()


def crack_sha1_hash(hash, use_salts=False):
    """
    Cracks passwords encrypted with SHA-1
    Based on: https://github.com/letientai299/freecodecamp/blob/master/infosec/pwcracker/password_cracker.py#L6

    Args:
        hash (str):                 Represents the hash to find
        use_salts (bool, optional): Deterimes if salt was used. Defaults to False

    Returns:
        str:    Returns the password that was deciphered or "PASSWORD NOT IN DATABASE"
    """
    hs = salted_hashes if use_salts else hashes
    return "PASSWORD NOT IN DATABASE" if not hs.get(hash) else hs.get(hash)
