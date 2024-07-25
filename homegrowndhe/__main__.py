from pprint import pprint
from os import get_terminal_size as gts
from collections import Counter

from homegrowndhe.dhe import generate_large_prime_parameters, DiffieHellmanParticipant

DEV_TEST = 1

def twidth():
    return gts().columns

def cprint(*args, padding=3, **kwargs):
    txt = " ".join(list(map(str, *args)))
    print(txt.center(twidth()-(padding*2), "=").center(twidth()))

def blockprint(txt):
    cprint("", padding=0)
    cprint(f" {txt} ", padding=0)
    cprint("", padding=0)

def p_print(*args, **kwargs):
    if not DEV_TEST:
        return
    try:
        if kwargs.keys():
            raise TypeError()
        pprint(*args)
    except (TypeError, AttributeError):
        print(*args, **kwargs)

def main() -> int:
    """
    Main function to demonstrate Diffie-Hellman key exchange between two participants.

    :returns: An integer exit code. A non-zero exit code indicates an error.
    """
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

def test_end_to_end(iterations):
    p_print("Starting end to end tests...")
    test_results = []
    for test in range(iterations):
        test_num = f" [{test+1}/{iterations}] "
        print("\n")
        cprint(f"{test_num}", padding=4)
        test_results.append(main())
    results = Counter(map(lambda v: 'Failed' if int(v) else 'Passed', test_results))
    blockprint("Tests Complete!")
    

if __name__ == "__main__":
    if DEV_TEST:
        test_end_to_end(20)
    else:
        main()
    