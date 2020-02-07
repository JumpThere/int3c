# int3c
Snippets about recent Malware Analysis: ELF executable.

Abstract about this malware:

Binary 'santa' is a part of Holiday Hack challenge which aims to test an individual's ability to find out the Dyanamically generated stacks'.

This sample scores a moderate score as this is firstly a Linux ELF and market doesn't still support ELF sandboxes easily. This leads to a possible pwn.

Code analogy:

 - readelf to find the imports the binary has
 - radare2 in debugging mode to see how the binary behaves on execution
 - radare2 ./santa
 - Make a list of imports/calls the binary has
 - Invoke r2 on debug mode:
         # r2 -d ./santa
         # aa # analyze functions and calls
         # Set a breakpoint to sym.<network>.send function.
         # run the binary
         # dc
         # Wait until the breakpoint is hit.
         # Go visual
         # v!
         # Navigate the stack panel and grab the https://pastebin[]com/XXXXX IoCs
 
 Note: Observe the breakpoints targetting the network calls. Multiple breakpoints could be set using 'db' instruction and you can toggle it with 'db -<sym.function>' argument.
         
         
EoF - JumpThere


