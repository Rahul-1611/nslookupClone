import sys
import random
import time
import socket
import struct


query_hostname = input("Enter <hostname> to query: ")

def createQueryHeader():
    print("Preparing DNS query ...")
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
    return query


def sendQuery(queryMsg):
    print("Contacting DNS server ...")
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
                print("Sending DNS query ...")
                connection.sendto(queryMsg,(dns_server, dns_port))

                #res
                res,_ = connection.recvfrom(512)
                print((f"DNS response received (attempt {attempt+1} of 3)"))
                return processResponse(res)
            except socket.timeout:
                print(f"{attempt + 1 } has timed out. Last {max_attempt - (attempt + 1)} attempts left...\n")
                attempt += 1
                if attempt > max_attempt:
                    print("Tried 3 times. DNS query has officially failed and terminated.")
                    return None
            except Exception as e:
                print(e)
                return None
    

def processResponse(response):
    #Unpacking header 
    print("Processing Response...")
    try:
        # Unpack the header fields (first 12 bytes)
        header = struct.unpack('!HHHHHH', response[:12])
        
        #Header values
        ID = header[0]
        flags = header[1]
        QDCOUNT = header[2]
        ANCOUNT = header[3]
        NSCOUNT = header[4]
        ARCOUNT = header[5]
        
        # Decoding flags
        QR = (flags >> 15) & 1
        OPCODE = (flags >> 11) & 0xF
        AA = (flags >> 10) & 1
        TC = (flags >> 9) & 1
        RD = (flags >> 8) & 1
        RA = (flags >> 7) & 1
        Z = (flags >> 4) & 0x7
        RCODE = flags & 0xF

        print("-" * 50)
        print("DNS Response Fields:")
        print("-" * 50)
        print("\nHEADER SECTION")
        print("-" * 50)
        print(f"header.ID = {ID}")
        print(f"header.QR = {QR}")
        print(f"header.OPCODE = {OPCODE}")
        print(f"header.AA = {AA}")
        print(f"header.TC = {TC}")
        print(f"header.RD = {RD}")
        print(f"header.RA = {RA}")
        print(f"header.Z = {Z}")
        print(f"header.RCODE = {RCODE}")
        print(f"header.QDCOUNT = {QDCOUNT}")
        print(f"header.ANCOUNT = {ANCOUNT}")
        print(f"header.NSCOUNT = {NSCOUNT}")
        print(f"header.ARCOUNT = {ARCOUNT}")
        
        #Unpacking Question 
        offset = 12  #due to header
        
        print("\nQUESTION SECTION")
        print("-" * 50)
        for _ in range(QDCOUNT):
            qname, offset = extractDomainName(response, offset)
            qtype, qclass = struct.unpack('!HH', response[offset:offset+4])
            offset += 4
            
            print(f"question.QNAME = {qname}")
            print(f"question.QTYPE = {qtype}")
            print(f"question.QCLASS = {qclass}")
        
        #Unpacking Ans
        print("\nANSWER SECTION")
        print("-" * 50)
        for _ in range(ANCOUNT):
            name, offset = extractDomainName(response, offset)
            ansData = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10
            
            atype = ansData[0]
            aclass = ansData[1]
            ttl = ansData[2]
            rdlength = ansData[3]
            

            if atype == 1:  # A Record (IPv4)
                rdata = socket.inet_ntoa(response[offset:offset+4])  # Assign directly to rdata
                offset += rdlength
            else:  # Non-IP data, e.g., CNAME with possible compression
                rdata, offset = extractDomainName(response, offset)
            
            print(f"answer.NAME = {name}")
            print(f"answer.TYPE = {atype}")
            print(f"answer.CLASS = {aclass}")
            print(f"answer.TTL = {ttl}")
            print(f"answer.RDLENGTH = {rdlength}")
            print(f"answer.RDATA = {rdata}")
            
    except Exception as e:
        print(f"Error processing response: {e}")

#Helper function to extract domain name
def extractDomainName(response, offset):
    labels = []
    original_offset = offset  #For debugging
    
    while True:
        length = response[offset]
        
        if length == 0:  # End of name
            offset += 1
            break
            
        # Checking for compression
        elif (length & 0xC0) == 0xC0:
            pointer = struct.unpack('!H', response[offset:offset+2])[0] & 0x3FFF
            labels.extend(extractDomainName(response, pointer)[0].split('.'))
            offset += 2
            break
            
        else:  # Regular label
            offset += 1
            labels.append(response[offset:offset+length].decode('ascii'))
            offset += length
            
    return '.'.join(labels), offset


print(sendQuery(generateQuery()))