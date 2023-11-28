import time
import random
from Crypto.Hash import SHA256
from chebyshev import chebyshev, int_to_bytes
import sys

#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, t = int(lines[0]), int(lines[1]), int(lines[2])

#FS actions as follow and sends message to GA
#GA_msg = D(GA_msg, FSpk)
with open('ga_auth_1.txt', 'r') as auth1:
    lines = auth1.readlines()
    ga_ts,ga_h,Qr,GA_id = int(lines[0]), int(lines[1]), int(lines[2]),int(lines[3])

#print(ga_ts,ga_h,Qr,GA_id)

#ts-GA_ts <= t?
fs_ts = int(time.time())
if fs_ts-ga_ts > t:
      print('invalid timestamp')
      sys.exit()
print('valid timestamp')
#GA_h == GA_hn?
ga_hn = SHA256.new(int_to_bytes(GA_id)+int_to_bytes(Qr)).digest()
if ga_hn != int_to_bytes(ga_h):
      print('invalid hash, reject session')
      sys.exit()
print('valid hash')
#Random number s
s = random.randint(10**3, 10**5)
Qs = chebyshev(s, x, p)
#FS_msg = FS_id,H(FS_id),Qs(x)
fs_id = ('enter fs id: ').encode('utf-8')
hfs_id = SHA256.new(fs_id).digest()
#FS_msg, H(FS_msg, Qr(x))
fs_msg = fs_id+hfs_id+int_to_bytes(Qs)
hmsg = SHA256.new(fs_msg+int_to_bytes(Qr)).digest()
lines = [str(int.from_bytes(fs_id)),'\n', str(int.from_bytes(hfs_id)),'\n', str(Qs),\
         '\n',str(int.from_bytes(fs_msg)),'\n',str(int.from_bytes(hmsg))]

with open('ga_auth_2.txt', 'w') as auth2:
      auth2.writelines(lines)
#Save fs's data
with open('fs_data.txt', 'w') as fs:
    fs.writelines([str(int.from_bytes(fs_id)), '\n',str(GA_id),'\n',str(s),'\n', str(Qs),'\n', str(Qr)])