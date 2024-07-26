# HomegrownDHE

HomegrownDHE is a Python package that provides an implementation of the Diffie-Hellman key exchange algorithm. It is designed for educational purposes and demonstrates how two participants can securely exchange cryptographic keys over an insecure channel.

[![Tests (Conda)](https://github.com/DJStompZone/HomeGrownDHE/actions/workflows/test-conda.yml/badge.svg)](https://github.com/DJStompZone/HomeGrownDHE/actions/workflows/test-conda.yml) [![CodeQL](https://github.com/DJStompZone/HomeGrownDHE/actions/workflows/codeql.yml/badge.svg)](https://github.com/DJStompZone/HomeGrownDHE/actions/workflows/codeql.yml)
## Installation

To install the package from PyPI, use the following command:

```sh
pip install homegrowndhe
```

## Usage

The package provides a main script to demonstrate the Diffie-Hellman key exchange, as well as utility functions for testing and debugging.

### Running the Main Script

To run the main script, simply execute the `__main__.py` file:

```sh
python -m homegrowndhe
```

This will perform a Diffie-Hellman key exchange between two participants and print the results to the console.

### Development Mode

To enable development mode, set the `DEV_TEST` environment variable to `True`. This will enable additional debug output and run the end-to-end tests:

```sh
export DEV_TEST=True
python -m homegrowndhe
```

### Detailed Usage

Here is a detailed breakdown of the available functions and their usage:

#### `main(test_iters=0) -> int`

The main function to demonstrate the Diffie-Hellman key exchange between two participants.

- `test_iters`: Number of test iterations to run. Defaults to `TEST_ITERATIONS`.
- Returns an integer exit code. A non-zero exit code indicates an error.

#### `test_end_to_end(iterations=1)`

Function to perform end-to-end tests of the Diffie-Hellman key exchange.

- `iterations`: Number of test iterations to run. Defaults to 1.

### Utility Functions

The package includes several utility functions for terminal output and numeric operations:

- `twidth()`: Returns the terminal width.
- `cprint(*args, padding=3, **kwargs)`: Centered print with padding.
- `blockprint(txt)`: Block print with centered text.
- `p_print(*args, **kwargs)`: Pretty print for development mode.
- `get_digits(s: str) -> str`: Extracts digits from a string.
- `is_long_num(_s: str, min_d: int = 100) -> bool`: Checks if a string contains a long numeric value.
- `get_long_numerics(s: str, min_d: int = 100) -> List[str]`: Extracts long numeric values from a string.

### Diffie-Hellman Key Exchange Classes

#### `DiffieHellmanParticipant`

A class representing a participant in the Diffie-Hellman key exchange.

- `__init__(self, parameters: DSA.DsaKey)`: Initializes a participant with given DSA parameters.
- `compute_shared_key(self, other_public_key: int) -> int`: Computes the shared key using the other participant's public key.

#### `generate_large_prime_parameters(bits: int = 2048) -> DSA.DsaKey`

Generates large prime parameters for the Diffie-Hellman key exchange.

- `bits`: The number of bits for the prime number. Defaults to 2048.

### Testing

To run the tests, use the following command:

```sh
pytest
```

This will execute the tests defined in the `test_homegrowndhe.py` file.

## License

This project is licensed under the MIT License.
```

Feel free to modify the README to suit your specific needs or add more sections if necessary.