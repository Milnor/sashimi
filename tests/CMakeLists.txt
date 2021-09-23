project(SashimiTests LANGUAGES C)
add_executable(test_all tests.c)
target_link_libraries(test_all PRIVATE rawfish)
add_test(NAME test_all COMMAND test_all)
