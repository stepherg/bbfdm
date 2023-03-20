# USPD Tests
USPD module test is based on `iopsys/code-analysis-dev` docker image. It consists
of below test phases, in each phase different kind of test perform:

1. Static code analysis
2. Unit Test
3. API Test
4. Functional Test

## 1. Static code Analysis
In this stage code is being tested for flaws by running static code analysers,
it also runs CPD tests which determine the optimal reusable codes.
Tests running in this phase are:

 - Flaw finder
 - CPP Check
 - CPD Test

## 2. Unit Test
In this stage various wrapper functions being tested for memory leaks using
`valgrind`.
Tests running in this phase are:
 - Cmocka Test cases
 - Coverage report
 - memory check using valgrind

## 3. API Test
In this stage ubus exposed APIs getting tested using `ubus-api-validator`

## 4. Functional Test
In this stage functionality provided by uspd is getting tested.

Below tests and verifications done in this stage:
- Compilation check
- Python based bug verification
- Functionality testing based on schema validation



