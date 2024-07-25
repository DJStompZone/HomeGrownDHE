from Cryptodome.PublicKey import DSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import bytes_to_long
from typing import Tuple

class DiffieHellmanParticipant:
    def __init__(self, parameters: DSA.DsaKey):
        self.parameters = parameters
        self.p = parameters.p
        self.g = parameters.g
        self.private_key = bytes_to_long(get_random_bytes(256))
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_key(self, other_public_key: int) -> int:
        """
        Computes the shared key using the other participant's public key.

        Args:
            other_public_key (int): The public key of the other participant.

        Returns:
            int: The computed shared secret key.
        """
        shared_key = pow(other_public_key, self.private_key, self.p)
        return shared_key

def generate_large_prime_parameters(bits: int = 2048) -> DSA.DsaKey:
    """
    Generates a large prime number and generator using PyCryptodome.

    Args:
        bits (int): The number of bits for the prime number.

    Returns:
        DSA.DsaKey: The DSA construct object containing the prime number and generator.
    """
    parameters = DSA.generate(bits)
    return parameters