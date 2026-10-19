
# SIEM Dataset and Preprocessing Test Cases

| Test ID | Test Scenario | Expected Result | Status |
|---|---|---|---|
| TC01 | Valid successful login | Record accepted | PASS - Verified |
| TC02 | Five failed logins for the same user and IP within 5 minutes | High-severity repeated-login alert | PASS - Verified |
| TC03 | Failed logins against five different users from one IP within 10 minutes | High-severity multiple-users alert | PASS - Verified |
| TC04 | Successful login after five failed attempts | High-severity alert | PASS - Verified |
| TC05 | Invalid source IP address | Record rejected and saved to invalid_logs.csv | PASS - Verified |
| TC06 | Missing username | Record rejected | Pending verification |
| TC07 | Invalid timestamp format | Record rejected | Pending verification |
| TC08 | Missing required CSV column | Preprocessing reports a missing-column error | Pending verification |

## Test Summary

The current dataset contains 14 records, of which 13 are valid and 1 is invalid.

The existing program has demonstrated the three suspicious login detection scenarios and rejected an invalid IP address.

The remaining test cases must be run separately before their status can be marked as verified.
