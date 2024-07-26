import pytest
from unittest.mock import patch
from io import StringIO
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters
from homegrowndhe.dhe import DiffieHellmanParticipant, make_client, make_server
from homegrowndhe.main import main, test_end_to_end
from homegrowndhe import TEST_ITERATIONS
from homegrowndhe.util import get_long_numerics

def test_generate_large_prime_parameters():
    """
    Tests that generate_large_prime_parameters returns valid DH parameters.
    """
    parameters = DiffieHellmanParticipant.generate_large_prime_parameters()
    assert isinstance(parameters, DHParameters)

def test_diffie_hellman_participant():
    """
    Tests that Diffie-Hellman participants can compute matching shared keys.
    """
    parameters = DiffieHellmanParticipant.generate_large_prime_parameters()
    participant_a = DiffieHellmanParticipant(parameters=parameters, role="Client")
    participant_b = DiffieHellmanParticipant(parameters=parameters, role="Server")

    shared_key_a = participant_a.compute_shared_key(participant_b.public_key_bytes())
    shared_key_b = participant_b.compute_shared_key(participant_a.public_key_bytes())
    
    assert shared_key_a == shared_key_b

def test_make_server():
    """
    Tests that make_server creates a DiffieHellmanParticipant with the Server role.
    """
    server = make_server()
    assert server.role == "Server"
    assert isinstance(server, DiffieHellmanParticipant)
    assert isinstance(server.parameters, DHParameters)

def test_make_client():
    """
    Tests that make_client creates a DiffieHellmanParticipant with the Client role.
    """
    server_parameters = DiffieHellmanParticipant.generate_large_prime_parameters()
    client = make_client(server_parameters)
    assert client.role == "Client"
    assert isinstance(client, DiffieHellmanParticipant)
    assert client.parameters.parameter_numbers().p == server_parameters.parameter_numbers().p
    assert client.parameters.parameter_numbers().g == server_parameters.parameter_numbers().g

@patch('sys.stdout', new_callable=StringIO)
def test_main_valid_run(mock_stdout):
    """
    Tests that the main function runs correctly and prints the secret keys.
    """
    main(TEST_ITERATIONS)
    output = mock_stdout.getvalue()
    assert "Beginning a Diffie-Hellman exchange..." in output
    assert "Parameters: g:" in output
    assert "Server's public key:" in output
    assert "Client's public key:" in output
    assert "Diffie-Hellman exchange completed" in output
    assert "Participant A's computed shared key:" in output
    assert "Participant B's computed shared key:" in output
    assert "Do the keys match? True" in output

@patch('sys.stdout', new_callable=StringIO)
def test_test_end_to_end(mock_stdout):
    """
    Tests that the end to end tests run correctly and print the secret keys.
    """
    test_end_to_end()
    output = mock_stdout.getvalue()
    print("Captured output from test_end_to_end:", output)
    assert 'Beginning a Diffie-Hellman exchange...' in output, "End to end test was never started"
    assert "Parameters: g:" in output
    assert "Server's public key:" in output
    assert "Client's public key:" in output
    assert "Diffie-Hellman exchange completed" in output
    assert "Participant A's computed shared key:" in output, "Missing A's key in output"
    assert "Participant B's computed shared key:" in output, "Missing B's key in output"
    assert "Do the keys match? True" in output, "Keys did not match"
    output_keys = get_long_numerics(output)
    assert output_keys, "Missing actual keys in output"
    assert len(output_keys) == 5, "Expected exactly 3 long numeric values in output"
    _p, server_pub, client_pub, shared1, shared2 = output_keys
    assert shared1 == shared2, "Keys A and B did not match"
    assert server_pub != client_pub, "Server and client public keys should not match"
    assert ('Tests Complete!' in output or "T e s t s   C o m p l e t e !" in output), "Missing test completion messages in output"

def assert_dhe_exchange_started(output):
    assert 'Beginning a Diffie-Hellman exchange...' in output, "End to end test was never started"

def assert_parameters_logged(output):
    assert "Parameters: g:" in output, "Parameters were not logged"

def assert_server_public_key(output):
    assert "Server's public key:" in output, "Missing server's public key in output"

def assert_client_public_key(output):
    assert "Client's public key:" in output, "Missing client's public key in output"

def assert_exchange_completed(output):
    assert "Diffie-Hellman exchange completed" in output, "Exchange completion message missing"

def assert_participant_a_key(output):
    assert "Participant A's computed shared key:" in output, "Missing A's key in output"

def assert_participant_b_key(output):
    assert "Participant B's computed shared key:" in output, "Missing B's key in output"

def assert_keys_match_message(output):
    assert "Do the keys match? True" in output, "Keys did not match"

def assert_keys_present(output):
    output_keys = get_long_numerics(output)
    assert output_keys, "Missing actual keys in output"
    assert len(output_keys) == 5, "Expected exactly 5 long numeric values in output"

def assert_keys_match(output):
    output_keys = get_long_numerics(output)
    _, server_pub, client_pub, shared1, shared2 = output_keys
    assert server_pub != client_pub, "Server and client public keys should not match"
    assert shared1 == shared2, "Keys A and B did not match"

def assert_test_completion(output):
    assert ('Tests Complete!' in output or "T e s t s   C o m p l e t e !" in output), "Missing test completion messages in output"

@pytest.mark.parametrize("assertion_func", [
    assert_dhe_exchange_started,
    assert_parameters_logged,
    assert_server_public_key,
    assert_client_public_key,
    assert_exchange_completed,
    assert_participant_a_key,
    assert_participant_b_key,
    assert_keys_match_message,
    assert_keys_present,
    assert_keys_match,
    assert_test_completion,
])
@patch('sys.stdout', new_callable=StringIO)
def test__end_to_end(mock_stdout, assertion_func):
    test_end_to_end()
    output = mock_stdout.getvalue()
    print("Captured output from test__end_to_end:", output)
    assertion_func(output)

if __name__ == "__main__":
    pytest.main()
