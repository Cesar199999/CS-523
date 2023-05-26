pytest test_credential_benchmark.py -k test_key_generation_benchmarks --benchmark-columns=mean,stddev && \
pytest test_credential_benchmark.py -k test_issuance_benchmarks --benchmark-columns=mean,stddev && \
pytest test_credential_benchmark.py -k test_showing_benchmarks --benchmark-columns=mean,stddev && \
pytest test_credential_benchmark.py -k test_verification_benchmarks --benchmark-columns=mean,stddev