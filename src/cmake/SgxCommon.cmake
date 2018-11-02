# The building constants and logic are adapted from Intel's sample code:
#
# https://github.com/intel/linux-sgx/blob/1ccf25b64a/SampleCode/RemoteAttestation/Makefile

set(SGX_SDK "$ENV{SGX_SDK}")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
set(SGX_LIBRARY_PATH "${SGX_SDK}/lib64")
set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x64/sgx_sign")

set(SGX_COMMON_CFLAGS "-m64" "-O0" "-g")

set(TRTS_LIBRARY_NAME "sgx_trts_sim")
set(URTS_LIBRARY_NAME "sgx_urts_sim")
set(SERVICE_LIBRARY_NAME "sgx_tservice_sim")
set(UAE_SERVICE_LIBRARY_NAME "sgx_uae_service_sim")
set(CRYPTO_LIBRARY_NAME "sgx_tcrypto")
set(TKEY_EXCHANGE_LIBRARY_NAME "sgx_tkey_exchange")
set(UKEY_EXCHANGE_LIBRARY_NAME "sgx_ukey_exchange")
