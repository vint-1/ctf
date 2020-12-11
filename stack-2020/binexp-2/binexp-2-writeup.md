# STACK 2020: Beta Reporting System

## *Overview*

#### The Challenge

We are given a binary file, which is a copy of what is running on a server. Our task is to identify and exploit the binary, in order to retrieve a flag on the server.

## *The Solution*

If we open up the binary file using something like Ghidra, we find a line that is vulnerable to a format string attack.

Moreover, there is a function "unknown_function" that will print the flag, but is normally not called by the program. So our exploit uses the format string attack to overwrite the return address, and allow us to jump to this function.

