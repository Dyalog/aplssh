:Namespace direct_tcpip
    keyfile1←'/home/marinus/.ssh/id_ecdsa.pub'
    keyfile2←'/home/marinus/.ssh/id_ecdsa'
    
    username←'marinus'
    password←''
    
    server_ip←'127.0.0.1'
    local_listenip←'127.0.0.1'
    local_listenport←2222
    
    remote_desthost←'localhost'
    remote_destport←22
    
    ∇ direct_tcpip;sock;session;auth_list
        ⍝ initialize SSH library
      #.SSH.Init
     
        ⍝ set up an SSH connection and do a handshake
      session←⎕NEW #.SSH.Session(server_ip 22)
     
        ⍝ show the hostkey hash
        ⍝ (authentication has not yet been done)
      ⎕←session.HostkeyHash'SHA1'
     
        ⍝ check what authentication methods are available
      auth_list←session.UserauthList
      ⎕←'Authentication methods:',auth_list
     
     
     
    ∇
:EndNamespace
