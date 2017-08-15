⍝∇:require =/../SSH.dyalog

:Namespace SCP
    ⍝ Sample showing how to do a simple SCP transfer
    
    _user←'marinus'
    _pass←''
    _pub←'/home/marinus/apl_sshid/id_rsa.pub'
    _priv←'/home/marinus/apl_sshid/id_rsa'
    _host←'localhost'
    _port←22
    
    _a←_user _pass _pub _priv _host _port
    
    ∇ data←a SCP path;user;pass;pub;priv;host;port;session;chan;stat;size;data;amt;agn;d
        ⍝ arguments
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
     
      chan stat←session.SCP_Recv path
      ⎕←'File size: ',size←1⊃stat
     
      data←⍬
     
      :While (≢data)<size
          amt←size-≢data
          ⎕←'Need ',amt,' bytes.'
          agn d←chan.Read amt
          data,←d
          ⎕←'Read',(≢d),'bytes, for a total of',(≢data),'.'
      :EndWhile
     
     shutdown:
     
    ∇
        
        
        
:EndNamespace
