## Tools

I used ChatGPT to understand the assignment requirements, review the Python implementation, and help debug the code. I also used Python and pytest to run the tests and verify the CLI output.

## What AI got wrong

The AI initially treated passing the public tests as a strong indication that the implementation was complete. However, passing these tests does not guarantee that all hidden requirements are satisfied. I used the assignment requirements and CLI output to identify the need for further validation.

## In my own words

1. I would fix the MD5 issue in `etag()` first because it is rated HIGH and could weaken the integrity of the application's ETag mechanism. The DB_PASSWORD issue is also important because hardcoded credentials can expose sensitive information, so it should be fixed as well.

2. A suppression needs an expiry date to make sure security findings are not ignored permanently. It ensures that exceptions are reviewed again after a limited period and that accepted risks do not remain forgotten.
