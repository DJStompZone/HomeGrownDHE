from homegrowndhe.main import main, test_end_to_end
from homegrowndhe import DEV_TEST, TEST_ITERATIONS


if __name__ == "__main__":
    if DEV_TEST:
        test_end_to_end(TEST_ITERATIONS)
    else:
        main()
    
