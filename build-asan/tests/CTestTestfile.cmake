# CMake generated Testfile for 
# Source directory: /mnt/h/libpqc-dyber/tests
# Build directory: /mnt/h/libpqc-dyber/build-asan/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_kem "/mnt/h/libpqc-dyber/build-asan/tests/test_kem")
set_tests_properties(test_kem PROPERTIES  _BACKTRACE_TRIPLES "/mnt/h/libpqc-dyber/tests/CMakeLists.txt;25;add_test;/mnt/h/libpqc-dyber/tests/CMakeLists.txt;0;")
add_test(test_sig "/mnt/h/libpqc-dyber/build-asan/tests/test_sig")
set_tests_properties(test_sig PROPERTIES  _BACKTRACE_TRIPLES "/mnt/h/libpqc-dyber/tests/CMakeLists.txt;30;add_test;/mnt/h/libpqc-dyber/tests/CMakeLists.txt;0;")
add_test(test_hash "/mnt/h/libpqc-dyber/build-asan/tests/test_hash")
set_tests_properties(test_hash PROPERTIES  _BACKTRACE_TRIPLES "/mnt/h/libpqc-dyber/tests/CMakeLists.txt;36;add_test;/mnt/h/libpqc-dyber/tests/CMakeLists.txt;0;")
add_test(test_integration "/mnt/h/libpqc-dyber/build-asan/tests/test_integration")
set_tests_properties(test_integration PROPERTIES  _BACKTRACE_TRIPLES "/mnt/h/libpqc-dyber/tests/CMakeLists.txt;42;add_test;/mnt/h/libpqc-dyber/tests/CMakeLists.txt;0;")
add_test(test_fndsa_quick "/mnt/h/libpqc-dyber/build-asan/tests/test_fndsa_quick")
set_tests_properties(test_fndsa_quick PROPERTIES  _BACKTRACE_TRIPLES "/mnt/h/libpqc-dyber/tests/CMakeLists.txt;48;add_test;/mnt/h/libpqc-dyber/tests/CMakeLists.txt;0;")
