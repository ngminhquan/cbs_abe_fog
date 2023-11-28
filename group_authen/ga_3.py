from chebyshev import chebyshev, int_to_bytes
from Crypto.Hash import SHA256
import sys

#GA actions as follow and send verified message to FS
#Check H(FS_msg',Qr(x)) == H(FS_msg, Qr(x))?
#Compute Qrs(x) = Qr(Qs(x))
#GA_msg2 = GA_id+Qrs(x)

#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, t = int(lines[0]), int(lines[1]), int(lines[2])
#import ga data
with open('ga_data.txt', 'r') as ga:
        lines = ga.readlines()
        ga_id, r, Qr = int(lines[0]), int(lines[1]), int(lines[2])
#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, t = int(lines[0]), int(lines[1]), int(lines[2])
#Read msg from FS
with open('ga_auth_2.txt', 'r') as auth2:
    lines = auth2.readlines()
    fs_id,hfs_id,Qs,fs_msg, hmsg = int(lines[0]), int(lines[1]), int(lines[2]),int(lines[3]), int(lines[4])

#FS_msg = FS_id,H(FS_id),Qs(x)
fs_msgn = int_to_bytes(fs_id)+int_to_bytes(hfs_id)+int_to_bytes(Qs)
#Check H(FS_msg',Qr(x)) == H(FS_msg, Qr(x))?
hmsgn = SHA256.new(fs_msgn+int_to_bytes(Qr)).digest()
if hmsgn != int_to_bytes(hmsg):
       print('invalid hash, reject session')
       sys.exit()
print('valid hash')

#Compute Qrs(x) = Qr(Qs(x))
#GA_msg2 = GA_id+Qrs(x)
Qrs = chebyshev(r, Qs, p)
ga_msg2 = int_to_bytes(ga_id) + int_to_bytes(Qrs)
#GA sends to FS GA_msg2, H(GA_msg2, Qrs(x))
hmsg2=SHA256.new(ga_msg2+int_to_bytes(Qrs)).digest()
lines = [str(ga_id),'\n',str(Qrs),'\n',str(int.from_bytes(ga_msg2)),'\n',str(int.from_bytes(hmsg2))]
with open('ga_auth_3.txt', 'w') as auth3:
    auth3.writelines(lines)