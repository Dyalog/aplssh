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
