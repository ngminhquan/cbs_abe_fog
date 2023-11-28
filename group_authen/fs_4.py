import sys
from chebyshev import chebyshev, int_to_bytes
from Crypto.Hash import SHA256
#FS check session
#Verify msg2
#if Qrs(x) == Qsr(x):
#    Session authenticated
#else:
#    FS reject the session

#import fs data
with open('fs_data.txt', 'r') as fs:
        lines =fs.readlines()
        fs_id,ga_id, s, Qs, Qr = int(lines[0]), int(lines[1]), int(lines[2]), int(lines[3]), int(lines[4])
#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, t = int(lines[0]), int(lines[1]), int(lines[2])
with open('ga_auth_3.txt', 'r') as auth3:
    lines = auth3.readlines()
    ga_id1,Qrs,ga_msg2,hmsg2 = int(lines[0]), int(lines[1]), int(lines[2]),int(lines[3])

if ga_id1 != ga_id:
       print('invalid')
       sys.exit()
ga_msg2n = int_to_bytes(ga_id) + int_to_bytes(Qrs)
hmsg2n = SHA256.new(ga_msg2n+int_to_bytes(Qrs)).digest()
if int_to_bytes(hmsg2) != hmsg2n:
       print('invalid, reject session')
       sys.exit()
print('valid message')
#Compute Qsr and compare with Qrs
Qsr = chebyshev(s, Qr, p)
if Qsr != Qrs:
       print('FS reject the session')
else:
       print('Session authenticated')