⍝∇:require =/../SSH.dyalog

:Namespace SCPWrite
    ⍝ Sample showing how to do an SCP upload
    
    _user←'marinus'
    _pass←''
    _pub←'/home/marinus/apl_sshid/id_rsa.pub'
    _priv←'/home/marinus/apl_sshid/id_rsa'
    _host←'localhost'
    _port←22
    
    _a←_user _pass _pub _priv _host _port
    _w←'/home/marinus/scptest.txt' (8⊥6 4 4) (⎕UCS 'Hello!')
    
    ∇ a SCPWrite(path mode data);user;pass;pub;priv;host;port;session;chan;agn;wr
      (user pass pub priv host port)←a
     
      #.SSH.Init
     
      session←⎕NEW #.SSH.Session(host port)
      ⎕←'Fingerprint: ',session.HostkeyHash'SHA1'
     
        ⍝ Try password authentication
      :Trap #.SSH.SSH_ERR
          ⎕←'Trying password authentication...'
          session.Userauth_Password user pass
          →authenticated
      :Else
          ⎕←'Failed.'
      :EndTrap
     
        ⍝ Try publickey authentication
      :Trap #.SSH.SSH_ERR
          ⎕←'Trying public key authentication...'
          session.Userauth_Publickey user pub priv pass
          →authenticated
      :Else
          ⎕←'Failed.'
      :EndTrap
     
        ⍝ No authentication methods left.
      ⎕←'Cannot authenticate.'
      →shutdown
     
     authenticated:
      ⎕←'Authenticated.'
     
      ⎕←'SCP session waiting to send file.'
      chan←session.SCP_Send(path mode(≢data))
     
      ⎕←'Writing...'
        ⍝ Write all the data
      :While 0<≢data
          ⎕←(≢data),'bytes left.'
          agn wr←chan.Write data
          :If agn ⋄ :Continue ⋄ :EndIf
          data↓⍨←wr
          ⎕←'Wrote',(wr),'bytes.'
      :EndWhile
     
      ⎕←'Done.'
     
      ⎕←'Sending EOF...'
      chan.SendEOF
      ⎕←'Waiting for EOF...'
      chan.WaitEOF
      ⎕←'Waiting for channel to close...'
      chan.WaitClosed
      ⎕←'Done.'
     
     shutdown:
     
    ∇
        
:EndNamespace
