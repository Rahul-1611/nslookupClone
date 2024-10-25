import sys
import random
import time
import socket
import struct


query_hostname = input("Enter <hostname> to query: ")

def createQueryHeader():
    dns_ID = random.randint(0,2**16 - 1) # unique identifier
    q_QR = 0 # represent that this is query ( 1 for res)
    q_OPCODE = 0 # kind of query - std
    q_AA = 0 # for res (so currently 0)
    q_TC = 0 # for res (so currently 0)
    q_RA = 0 # for res (so currently 0)
    q_RCODE = 0 # for res (so currently 0)
    q_RD = 1 # recursion bit
    q_Z = 0 # future use (must be set 2 - 0)
    """
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |

    """
    q_flags = (q_QR << 15) | (q_OPCODE << 11 ) | (q_AA << 10 ) |(q_TC<<9) |(q_RD<<8) |(q_RA << 7)|(q_Z<<4)|(q_RCODE)
    q_QDCOUNT = 1 # no of queries ( v r asking only one domain name)
    q_ANCOUNT = 0 # for res (so currently 0)
    q_NSCOUNT = 0 # for res (so currently 0)
    q_ARCOUNT = 0 # for res (so currently 0)
    queryHeader = struct.pack('!HHHHHH',
                dns_ID,
                q_flags,
                q_QDCOUNT,
                q_ANCOUNT,
                q_NSCOUNT,
                q_ARCOUNT 
)
    print(queryHeader.hex())
    return queryHeader


def getQNAME():
    domainParts = query_hostname.split('.') #split for labels
    ans = []
    for d in domainParts:
        ans.append(bytes([len(d)])+d.encode('ascii')) # add its len + part in ascii (3edu2ed..)
    ans.append(b'\x00') # null char in end
    qname = b''.join(ans) # everything should be in byte format
    return qname


def createQueryQuestion():
    q_QNAME = getQNAME()
    q_QTYPE = 1
    q_QCLASS = 1
    queryQuestion = q_QNAME + struct.pack('!HH',    #q_Qname already in correct format
        q_QTYPE,
        q_QCLASS
    )
    print(queryQuestion.hex)
    return queryQuestion


def generateQuery():
    query = createQueryHeader() + createQueryQuestion();
    print(query.hex())
    return query


def sendQuery(queryMsg):
    dns_server = "8.8.8.8"
    dns_port = 53 #default port of dns server for receiving queries
    max_attempt = 3
    attempt = 0 
    

    # # creating connection         Ipv4           UDP
    # connection = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) 

    # #setting timeout 5s
    # connection.settimeout(5)

    #new method
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)

        while attempt < max_attempt:
            try:
                #sending query 
                connection.sendto(queryMsg,(dns_server, dns_port))

                #res
                res,_ = connection.recvfrom(512)
                print((f"Response received on {attempt+1} attempt."))
                return res
            except socket.timeout:
                print(f"{attempt + 1 } has timed out. {max_attempt - (attempt + 1)} attempts left.")
                attempt += 1
                if attempt > max_attempt:
                    print("Tried 3 times. DNS query has officially failed and terminated.")
                    return None
            except Exception as e:
                print(e)
                return None
    


print(sendQuery(generateQuery()))