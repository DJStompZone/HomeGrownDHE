import pytest
from Cryptodome.PublicKey import DSA
from unittest.mock import patch
from io import StringIO

from homegrowndhe.dhe import generate_large_prime_parameters, DiffieHellmanParticipant
from homegrowndhe.main import main, test_end_to_end
from homegrowndhe import TEST_ITERATIONS, DEV_TEST
from homegrowndhe.util import twidth, get_long_numerics

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
    main(TEST_ITERATIONS)
    output = mock_stdout.getvalue()
    assert "Participant A's computed shared key: " in output
    assert "Participant B's computed shared key: " in output

@patch('sys.stdout', new_callable=StringIO)
def test_test_end_to_end(mock_stdout):
    """
    Tests that the end to end tests run correctly and print the secret keys.
    """
    test_end_to_end()
    output = mock_stdout.getvalue()
    assert 'Beginning a Diffie-Hellman exchange...' in output, "End to end test was never started"
    assert "Participant A's computed shared key:" in output, "Missing A's key in output"
    assert "Participant B's computed shared key:" in output, "Missing B's key in output"
    output_keys = get_long_numerics(output)
    assert output_keys, "Missing actual keys in output"
    assert len(output_keys) > 1, "Too few keys in output"
    assert len(output_keys) < 3, "Too many keys in output"
    key_a, key_b = output_keys
    assert key_a == key_b, "Keys A and B did not match"
    assert all([
        'Diffie-Hellman exchange completed' in output, 
        any([
            "T e s t s   C o m p l e t e !" in output, 
            "Tests Complete!" in output
        ])
    ]), "Missing test completion messages in output"

def assert_dhe_exchange_started(output):
    assert 'Beginning a Diffie-Hellman exchange...' in output, "End to end test was never started"

def assert_participant_a_key(output):
    assert "Participant A's computed shared key:" in output, "Missing A's key in output"

def assert_participant_b_key(output):
    assert "Participant B's computed shared key:" in output, "Missing B's key in output"

def assert_keys_present(output):
    output_keys = get_long_numerics(output)
    assert output_keys, "Missing actual keys in output"
    assert len(output_keys) > 1, "Too few keys in output"
    assert len(output_keys) < 3, "Too many keys in output"

def assert_keys_match(output):
    output_keys = get_long_numerics(output)
    key_a, key_b = output_keys
    assert key_a == key_b, "Keys A and B did not match"

def assert_test_completion(output):
    assert all([
        'Diffie-Hellman exchange completed' in output, 
        any([
            "T e s t s   C o m p l e t e !" in output, 
            "Tests Complete!" in output
        ])
    ]), "Missing test completion messages in output"

@pytest.mark.parametrize("assertion_func", [
    assert_dhe_exchange_started,
    assert_participant_a_key,
    assert_participant_b_key,
    assert_keys_present,
    assert_keys_match,
    assert_test_completion,
])
@patch('sys.stdout', new_callable=StringIO)
def test__end_to_end(mock_stdout, assertion_func):
    test_end_to_end()
    output = mock_stdout.getvalue()
    assertion_func(output)

if __name__ == "__main__":
    pytest.main()
