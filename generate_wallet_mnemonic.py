# This file contains functions to generate and validate a BIP39 mnemonic.
# This script runs offline

import binascii
from typing import Tuple
from bip_utils import Bip39MnemonicValidator, Bip39Mnemonic, Bip39WordsNum, Bip39Languages, Bip39MnemonicGenerator
from bip_utils.utils.mnemonic import Mnemonic
from coincurve import PrivateKey
from bip44 import Wallet as bip44Wallet
from bip44.utils import get_eth_addr


def generateValidMnemonic(wordsNumber: int) -> Tuple[bool, Mnemonic]:
    """
    Generate a valid BIP39 mnemonic with the specified number of words.

    Args:
    wordsNumber (int): The number of words to include in the generated mnemonic.

    Returns:
    Tuple[bool, Mnemonic]: A tuple containing a boolean value indicating 
    the validity of the mnemonic and the Mnemonic object.
    """
    # Generate a random mnemonic string of 12 words with default language (English)
    # A Mnemonic object will be returned
    mnemonic = Bip39MnemonicGenerator(
        Bip39Languages.ENGLISH
    ).FromWordsNumber(wordsNumber)

    if checkMnemonic(mnemonic):
        return True, mnemonic

    return False, None


def checkMnemonic(mnemonic: Mnemonic) -> bool:
    """
    Validate the given BIP39 mnemonic.

    Args:
    mnemonic (Mnemonic): The Mnemonic object to be validated.

    Returns:
    bool: True if the mnemonic is valid, False otherwise.
    """
    # Load the Mnemonic and check if it is valid
    mnemonic_to_validate = Bip39Mnemonic.FromList(mnemonic.ToList())

    return Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic_to_validate)


def derivateKeys(mnemonic_str: str) -> Tuple[str, str, str]:
    """
    Derive the Ethereum private key, public key, and address for the given mnemonic string.

    Args:
    mnemonic_str (str): The mnemonic string from which to derive the keys.

    Returns:
    Tuple[str, str, str]: A tuple containing the Ethereum address, private key (hex-encoded), 
    and public key (hex-encoded).

    Returns (None, None, None) if there's a mismatch between the derived private and public keys.
    """
    w = bip44Wallet(mnemonic_str)
    sk, pk = w.derive_account("eth", account=0)
    sk = PrivateKey(sk)

    if sk.public_key.format() == pk:
        return get_eth_addr(pk), sk.to_hex(), str(binascii.hexlify(pk), 'utf-8')
    else:
        return None, None, None


if __name__ == "__main__":
    is_valid = False

    # Keep generating mnemonics until a valid one is created
    while not is_valid:
        is_valid, mnemonic = generateValidMnemonic(Bip39WordsNum.WORDS_NUM_24)

    # Find the first Ethereum public key from the mnemonic
    eth_address, private_key, public_key = derivateKeys(mnemonic.ToStr())

    print("Generated mnemonic:")
    print(f"{mnemonic.ToStr()}")
    print("\nFirst Ethereum wallet address:")
    print(f"{eth_address}")
