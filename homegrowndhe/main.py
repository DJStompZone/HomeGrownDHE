from homegrowndhe.util import twidth, cprint, blockprint, p_print
from homegrowndhe.dhe import DiffieHellmanParticipant, generate_large_prime_parameters
from homegrowndhe import TEST_ITERATIONS

from collections import Counter

def main(test_iters=0) -> int:
    """
    Main function to demonstrate Diffie-Hellman key exchange between two participants.

    :returns: An integer exit code. A non-zero exit code indicates an error.
    """
    if not test_iters:
        test_iters = TEST_ITERATIONS
    p_print("Beginning a Diffie-Hellman exchange...")
    parameters = generate_large_prime_parameters()
    p_print("Parameters:", parameters)

    participant_a = DiffieHellmanParticipant(parameters)
    participant_b = DiffieHellmanParticipant(parameters)

    shared_key_a = participant_a.compute_shared_key(participant_b.public_key)
    shared_key_b = participant_b.compute_shared_key(participant_a.public_key)

    p_print(f"Participant A's computed shared key: {shared_key_a}")
    p_print(f"Participant B's computed shared key: {shared_key_b}")

    p_print("Diffie-Hellman exchange completed")

    return shared_key_a !=shared_key_b 

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