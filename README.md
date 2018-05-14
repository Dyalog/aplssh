## APLSSH

This is a wrapper around the `libssh2` library. Currently, it only exposes a small fraction of its functionality.
It can execute remote commands, and read and write files.

Example session:

```apl

      ⍝ connect to a host
      sess←⎕NEW SSH.Session ('10.0.60.249' 22)
      sess.HostkeyHash 'MD5'
85 246 47 235 173 71 184 56 162 14 123 196 75 109 197 123

      ⍝ authenticate
      sess.Userauth_Publickey 'marinus' '/home/marinus/apl_sshid/id_rsa.pub' '/home/marinus/apl_sshid/id_rsa' ''
      sess.Authenticated
1

      ⍝ run a command
      x←sess.Exec 'ls *.txt'
      ⍝ the first element contains the return code, the second element contains STDOUT (as bytes)
      x
┌─┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
│0│115 99 112 116 101 115 116 46 116 120 116 10 116 101 115 116 46 116 120 116 10 119 114 105 116 101 95 116 101 115 
└─┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────

      ─────────────────────┐
      116 46 116 120 116 10│
      ─────────────────────┘
      ⎕UCS 2⊃x
scptest.txt
test.txt
write_test.txt

      ⍝ read a file
      test_txt←sess.ReadFile 'test.txt'
      ⍝ the first element contains information about the file (size, mode, mtime, atime)
      ⍝ the second element contains the file's contents (as bytes)
      test_txt
┌───────────────────────────┬──────────────┐
│4 436 1503307650 1502811867│102 111 111 10│
└───────────────────────────┴──────────────┘
      ⎕UCS 2⊃test_txt
foo

      ⍝ write a file
      sess.WriteFile 'test2.txt' (⎕UCS 'This will be written.')
      ⍝ let's see if it's there
      ⎕UCS 2⊃sess.Exec'ls *.txt'
scptest.txt
test2.txt
test.txt
write_test.txt

      ⎕UCS 2⊃sess.Exec'cat test2.txt'
This will be written.
      
      sess.Disconnect ⍬
      
```

Also included is a version of `APLProcess` that supports SSH connections using these classes.

To start an APL process on a remote machine:

```apl
x←⎕NEW APLProcess (ws args (host user pubkey privkey executable))
```

E.g.:

```apl
x←⎕NEW APLPRocess ('~/Test.dws' '' ('10.20.30.40' 'marinus' 'id_rsa.pub' 'id_rsa' 'dyalog'))
```

### Third-party licences

Binary copies of [libssh2](https://www.libssh2.org/) included with aplssh are redistributed according to the following licence:

Copyright (c) 2004-2007 Sara Golemon <sarag@libssh2.org>  
Copyright (c) 2005,2006 Mikhail Gusarov <dottedmag@dottedmag.net>  
Copyright (c) 2006-2007 The Written Word, Inc.  
Copyright (c) 2007 Eli Fant <elifantu@mail.ru>  
Copyright (c) 2009-2014 Daniel Stenberg  
Copyright (C) 2008, 2009 Simon Josefsson  
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of any other contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
