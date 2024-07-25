import pytest
from Cryptodome.PublicKey import DSA
from unittest.mock import patch
from io import StringIO

from homegrowndhe.dhe import main, generate_large_prime_parameters, DiffieHellmanParticipant

def test_generate_large_prime_parameters():
    """
    Tests that generate_large_prime_parameters returns valid DSA parameters.
    """
    parameters = generate_large_prime_parameters()
    assert isinstance(parameters, DSA.DsaKey)

def test_diffie_hellman_participant():
    """
    Tests that Diffie-Hellman participants can compute matching shared keys.
    """
    parameters = generate_large_prime_parameters()
    participant_a = DiffieHellmanParticipant(parameters)
    participant_b = DiffieHellmanParticipant(parameters)

    shared_key_a = participant_a.compute_shared_key(participant_b.public_key)
    shared_key_b = participant_b.compute_shared_key(participant_a.public_key)
    
    assert shared_key_a == shared_key_b

@patch('sys.stdout', new_callable=StringIO)
def test_main_valid_run(mock_stdout):
    """
    Tests that the main function runs correctly and prints the secret keys.
    """
    main()
    output = mock_stdout.getvalue()
    assert "Participant A's computed shared key: " in output
    assert "Participant B's computed shared key: " in output

if __name__ == "__main__":
    pytest.main()