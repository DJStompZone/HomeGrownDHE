from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey, generate_parameters
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Literal, Optional

from homegrowndhe import DEV_TEST

class NoLogging:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def basicConfig(self, *args, **kwargs):
        pass

if DEV_TEST:
    import logging
    logging.basicConfig(encoding="utf-8", level=logging.DEBUG, filename="dhe.log", filemode="a", format="%(asctime)s [%(levelname)s] %(message)s")
else:
    logging = NoLogging()

class DiffieHellmanParticipant:
    def __init__(self, parameters: Optional[DHParameters] = None, role: Literal["Client", "Server"] = "Client"):
        self.role = role
        if parameters is None:
            if self.role == "Server":
                self.parameters = DiffieHellmanParticipant.generate_large_prime_parameters()
            else:
                raise ValueError("Client must be initialized with parameters.")
        else:
            self.parameters = parameters
        self.parameter_numbers = self.parameters.parameter_numbers()
        self.p = self.parameter_numbers.p
        self.g = self.parameter_numbers.g
        logging.debug(f"DiffieHellmanParticipant: p={self.p}, g={self.g}, role={self.role}")
        self._private_key: Optional[DHPrivateKey] = None
        self._public_key: Optional[DHPublicKey] = None

    @property
    def private_key(self) -> DHPrivateKey:
        if self._private_key is None:
            self._private_key = self.parameters.generate_private_key()
            logging.debug(f"DiffieHellmanParticipant ({self.role}): private_key generated.")
            return self._private_key
        logging.debug(f"DiffieHellmanParticipant ({self.role}): returning existing private key.")
        return self._private_key

    @private_key.setter
    def private_key(self, value: DHPrivateKey):
        raise AttributeError("Private key cannot be set directly.")

    @property
    def public_key(self) -> DHPublicKey:
        if self._public_key is None:
            if self.private_key is None:
                raise ValueError("Private key must be set before public key can be generated")
            self._public_key = self.private_key.public_key()
            logging.debug(f"DiffieHellmanParticipant ({self.role}): public_key generated.")
            return self._public_key
        logging.debug(f"DiffieHellmanParticipant ({self.role}): returning existing public key.")
        return self._public_key

    @public_key.setter
    def public_key(self, value: DHPublicKey):
        raise AttributeError("Public key cannot be set directly.")

    def compute_shared_key(self, other_public_key_bytes: bytes) -> bytes:
        other_public_key = serialization.load_der_public_key(other_public_key_bytes, backend=default_backend())
        shared_key = self.private_key.exchange(other_public_key)
        logging.debug(f"DiffieHellmanParticipant ({self.role}): shared_key computed.")
        return shared_key

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def generate_large_prime_parameters(bits: int = 2048, generator: int = 5) -> DHParameters:
        return generate_parameters(generator=generator, key_size=bits, backend=default_backend())


def make_server() -> DiffieHellmanParticipant:
    server = DiffieHellmanParticipant(role="Server")
    return server

def make_client(parameters: DHParameters) -> DiffieHellmanParticipant:
    client = DiffieHellmanParticipant(parameters=parameters, role="Client")
    return client