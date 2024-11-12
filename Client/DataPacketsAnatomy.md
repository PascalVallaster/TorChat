# Anatomy of packet send through the system

#### Notations:
#### Encrypted data is marked with an '!'

## Standard Data Packet (SDP)
### Anatomy

    {header}{payload}
    
    Header:
    {InternalCodes}  len:int=2 (4 bits)

    Payload:
    {data}  len=1_000_000_000 bytes


## Handshake Data Packets (HDP)
### Types
- Key transfer DPs (KTDP)
- Key transfer acknowledge DPs (KTACKDP)
- Encrypted  KTDPs and KTACKDPs

### Anatomy
#### KTDP:
    {key-payload}  len=56 bytes cryptografic ECDH key
#### KTACKDP / SDP
    {header}{!payload}

    Header: SDP header

    Payload: 
    {data}  len=128 bytes hashed cryptografic key

## Internal Codes
### Ordered in bit-occurrence left to right
- Encryption status / layer 1
- Encryption layer 2
- Destination
- Connection status - continue/tear-down
- Panik status

#### Encryption status / layer 1
**0 ...** data is not encrypted --> destination will be ignored as sending unencrypted traffic further than one node is prohibited
<br>
**1 ...** data is encrypted with at least one layer of encryption
#### Encryption layer 2
**0 ...** data is not encrypted with a second layer of encryption 
<br>
**1 ...** data is encrypted with a second layer of encryption 
#### Destination
**0 ...** data is addressed to server
<br>
**0 ...** data is addressed to client
#### Connection status
**0 ...** continue connection
<br>
**1 ...** tear-down connection
#### Panik status
**0 ...** continue connection
<br>
**1 ...** tear-down connection and erase everything --> implies tear-down is 1 regardless of actual connection status



    
    

    
