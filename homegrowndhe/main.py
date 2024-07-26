from homegrowndhe.util import cprint, blockprint, p_print
from homegrowndhe.dhe import make_client, make_server
from homegrowndhe import TEST_ITERATIONS

from collections import Counter

def main(test_iters=0) -> int:
    """
    Main function to demonstrate Diffie-Hellman key exchange between two participants.

    :returns: An integer exit code. A non-zero exit code indicates an error.
    """
    p_print("Beginning a Diffie-Hellman exchange...")
    if not test_iters:
        test_iters = TEST_ITERATIONS
   
    server = make_server()
    parameter_numbers = server.parameters.parameter_numbers()

    p_print(f"Parameters: g: {parameter_numbers.g} p: {parameter_numbers.p}")
    p_print(f"Server's public key: {int(server.public_key_bytes().hex(), 16)}")
    client = make_client(server.parameters)

    p_print(f"Client's public key: {int(client.public_key_bytes().hex(), 16)}")

    shared_key_a = client.compute_shared_key(server.public_key_bytes())
    shared_key_b = server.compute_shared_key(client.public_key_bytes())

    p_print("Diffie-Hellman exchange completed")
    p_print(f"Participant A's computed shared key: {int(shared_key_a.hex(), 16)}")
    p_print(f"Participant B's computed shared key: { int(shared_key_b.hex(), 16)}")
    p_print(f"Do the keys match? {shared_key_a == shared_key_b}")
    
    # 0 = good, 1 = bad (Unix convention)
    return shared_key_a != shared_key_b 

def test_end_to_end(iterations=1):
    p_print("Starting end to end tests...")
    test_results = []
    for test in range(iterations):
        test_num = f" [{test+1}/{iterations}] "
        print("\n")
        cprint(f"{test_num}", padding=4)
        test_results.append(main())
    results = Counter(map(lambda v: 'Failed' if int(v) else 'Passed', test_results))
    blockprint("Tests Complete!")