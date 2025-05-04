---
layout: post
title: mem-corruption lab RPISEC
date: 2023-12-04 
description: rpisec lab2C
categories: rpisec bin-exp
---


### Solving lab2C "02/13 | --[ Memory Corruption Lab" (https://github.com/RPISEC/MBE/blob/master/src/lab02/lab2C.c)

### This lab is a simple buffer-overflow. The intention of this lab was to explore bof and get a shell from the lab machine and then get the flag. But here we won't have the shell part.

First we go get the source code and compile following the instruction that is commented in the code:


![compilelab2ccode](https://github.com/geleiaa/blog-repo/blob/main/imgs/compilelab2ccode.png)


```
gcc -O0 -fno-stack-protector lab2C.c -o lab2C
```

Running the binary we see how to use it:


![binusage](https://github.com/geleiaa/blog-repo/blob/main/imgs/binusage.png)


Running with a string the binary shows that we are not "authenticated" and set_me is 0. It seems that the binary needs a specific string/password:


![noauth](https://github.com/geleiaa/blog-repo/blob/main/imgs/notauth.png)



Looking at the binary disassembly, we see that the **strcpy** function is called before a comparison of a memory address with the “0xdeadbeef” bytes. And if this comparison is not true, the flow jumps to the end, prints something and ends execution. But if the comparison is true, a "shell" function will be called.

```
$ objdump -dM intel lab2C | grep -A40 "<main>:"
```


![jmp](https://github.com/geleiaa/blog-repo/blob/main/imgs/jmp.png)



Looking at the disassembly of the shell function, we don't see much useful stuff, just a **puts** function that can display some string and we also see a **system** function being called.

```
$ objdump -dM intel lab2C | grep -A12 "<shell>:"
```


![disasshell](https://github.com/geleiaa/blog-repo/blob/main/imgs/disasshell.png)



### Now let's debug the binary to see what it does


Looking at the disassembly with gdb + peda we can better see the execution flow of the main function:


![gdbdisas](https://github.com/geleiaa/blog-repo/blob/main/imgs/gdbdisas.png)



Running the binary in gdb without passing any input string, the flow is diverted to a **printf** that shows the usage and then a jump throws the flow to the end of the execution:

* check input (**cmp DWORD PTR [rbp-0x24],0x2**)


![withoutarg](https://github.com/geleiaa/blog-repo/blob/main/imgs/withoutarg1.png)


* if not have input, print the usage


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/withoutarg2.png)


* jump to the end


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/withoutarg3.png)




### Since the binary needs an input let's set a breakpoint in the main and run binary with an input string...

```
gdb-peda$ b main
```
(breakpoint)

```
gdb-peda$ r GELEIA
```
(run binary with "GELEIA" string)


Now running with a input the exec flow throws us to another place. First compare if have any args, so **je** (jump equal) go to address **<main+59>**.


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/witharg1.png)



After some steps we arrive at the **strcpy** function that we saw before. We can see that the input is moved through the registers until it reaches the **strcpy** function. And probably the input is copied somewhere by the **strcpy** function. Soon after, a comparison of address **DWORD PTR [rbp-0x4]** with "0xdeadbeef" takes place.



![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/witharg2.png)



After comparing if **DWORD PTR [rbp-0x4]** address is equal to "0xdeadbeef" the flow jump to "shell" function. If not equal the flow jump to a **printf** with a message "Not authenticated. set_me was 0" and finishe execution.


* jump to end


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/witharg3.png)



* print message and finishes


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/witharg4.png)




### Now is the Buffer Overflow

Knowing that the given input is stored somewhere, we can overwrite the memory after the input is stored so we can control what will be compared. If this works, we will bypass the check.

First we need to know how many bytes can be stored in the variable (or how much memory has been allocated to that variable). To do this, we will send a large number of bytes to the binary input and see how it handles that.

The input will be this: "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE". 

This way we can know how many bytes the variable stores and when there was a memory leak. For example, if the variable stores the value until the end of the letters "B", then we know that after the "B" the memory following the variable was overwritten.


### Let's go

First let's run the binary with gdb then set a breakpoint in main and then send the buffer to the binary like this: 

```
gdb-peda$ r $(echo 'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE')
```


Getting close to the part that checks the input we can see the alphabet buffer being moved through the registers

* first buffer go to **RAX** after go to **RDX**


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/buffmove1.png)




![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/buffmove2.png)




Passing in **strcpy** function the buffer is stored and after this the address **DWORD PTR [rbp-0x4]** will be compared.



![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/compare1.png)



So if we look at what's at that address, we see the bytes that overwrote the memory after the leak:


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/compare2.png)



Basically the variable that stores the input has a limit of 15 bytes. Example:

```
AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE
|   1 to 15   ||       16 to 40        |
|_____________||_______________________|
this is stored  this overwrite the next memory

```

Knowing this we can overwrite the next memory (after 15 bytes) with the "0xdeadbeef" bytes and bypass the check. That way:

```
AAAAAAAABBBBBBB0xdeadbeef
```


### So let's go

Using a python code to make it easier, we will print the buffer and send it to the binary input. The exploit looks like this:

```py
import struct

buf = b''
buf += b'\x41' * 15
buf += struct.pack('<Q', 0xdeadbeef)

f = open("exp", "wb")
f.write(buf)
```

Running the exploit will send the buffer to a file called exp. And when we run the binary we will send the file contents to the input, like this:

```
gdb-peda$ r $(cat exp)
```

Then let's move on to the part that matters:

* we can see the exploration buffer being moved.


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/exp1.png)



* Coming to the comparison, we see that the buffer overwrote the variable where it is stored and went to the memory of the next instruction.


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/exp2.png)



![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/exp3.png)




* Since we have the memory overwritten, then the execution flow goes to the shell function as expected.


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/exp4.png)




![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/exp5.png)




* Now we get to the shell function and see what's in it.


![a](https://github.com/geleiaa/blog-repo/blob/main/imgs/exp6.png)



So it looks like we did this...

