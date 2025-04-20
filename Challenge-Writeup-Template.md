<img src='assets/banner.png' style='width:100%;' />

<img src='assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Manager Code Validator</font>

20 April 2025

Prepared By: `Figueron`

Challenge Author(s): `Figueron`

Difficulty: <font color='green'>Easy</font>

<br><br>


# Synopsis 

- You’re part of a red‑team engagement targeting a financial services firm. During your internal network pivot, you discover an ELF binary called manager_check on a payments server. The application prompts for a 12‑character manager code before approving high‑value transactions. The client has lost track of the original code, and you’ve been asked to recover it by reversing the binary locally.
## Description 
You are given manager_check, a no‑PIE, no‑canary ELF executable.
On execution it prints a banner and prompts:
```
Welcome to Manager Code Validator!
Enter the manager code:
```
If your 12‑byte input, when transformed via (c*23 + 60) mod 256, matches the embedded table, it prints:
```
Access granted! Code accepted: <your input>
```
Otherwise, it rejects you with “Access denied.”
The flag format is HTB{…} and is exactly 12 characters long.

## Skills Required 
- Basic C/C++ reading
- Familiarity with Ghidra/IDA for static disassembly
- Understanding of modular arithmetic and the extended Euclidean algorithm
- Python scripting for quick de‑encryption

## Skills Learned
1. How to spot and reverse an affine/linear congruential transform on bytes
2. Computing modular inverses modulo 256 via the extended Euclidean algorithm
3. Integrating a simple Python one‑liner into a pwn script

# Enumeration
- Running `file manager_check` shows a 64‑bit ELF, no PIE, no stack protector.
- `strings` manager_check reveals references to table, MUL, and ADD.
- Loading into Ghidra and navigating to main() uncovers the 12‑byte table and the two constants.

## Analyzing the source code
No source is shipped, but in Ghidra’s decompiler the core looks like:
```
const unsigned char table[12] = {
    0xB4,0xC8,0x2A,0x49,
    0x27,0x35,0x38,0xA3,
    0x1E,0xD1,0x7A,0x77
};
const unsigned char MUL = 23;
const unsigned char ADD = 60;

for (i = 0; i < 12; i++) {
    if ((input[i]*MUL + ADD & 0xFF) != table[i]) {
        puts("Access denied.");
        return 0;
    }
}
puts("Access granted! Code accepted: ");
puts(input);
```
From this we see the affine cipher: out = (in * 23 + 60) mod 256. Our goal is to invert that.

A little summary of all the interesting things we have found out so far:

1. The binary enforces exactly 12 characters.
2. It uses an LCT (not XOR) with multiplier 23 and increment 60.
3. The table bytes correspond to a printable flag in the form HTB{…}.

# Solution 
## Finding the vulnerability 

The validation function implements an affine transform rather than a XOR. Every input byte c is checked against `table[i] == (c*23 + 60) % 256`. Since 23 and 256 are coprime, we can compute the modular inverse of 23 modulo 256 and reverse the equation:
```
c ≡ ((table[i] - 60) * inv23) mod 256
```
This arithmetic flaw (use of a reversible bijection) means the secret code is recoverable in full once you identify MUL and ADD.

# Exploitation 
```
from pwn import *

r = remote("challenge.host", 1337)
r.recvuntil("manager code: ")
r.sendline(flag)
print(r.recvline())

# Compute modular inverse of 23 mod 256 (via extended Euclid):
# extended gcd to find inverse
def egcd(a, b):
    if b == 0: return (a,1,0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a//b)*y1)

g, inv23, _ = egcd(23, 256)
inv23 %= 256  # yields 167

# Invert each table byte:

table = [0xB4,0xC8,0x2A,0x49,0x27,0x35,0x38,0xA3,0x1E,0xD1,0x7A,0x77]
flag = "".join(
    chr(((b - 60) & 0xFF) * inv23 % 256)
    for b in table
)
print(flag)  # → HTB{Mod1n3r}
```
Submit HTB{Mod1n3r} to the binary:
```
    $ ./manager_check
    Welcome to Manager Code Validator!
    Enter the manager code: HTB{Mod1n3r}
    Access granted! Code accepted: HTB{Mod1n3r}
```
Flag: `HTB{Mod1n3r}`
