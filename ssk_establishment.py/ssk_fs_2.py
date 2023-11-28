#FS actions as follow anmd sends message to GA
#M ⊕ H(pw) = H(Qpw(x))
#generate Qq(x) with a random number q
#Hnew=H(Qpw(x))i⊕H(Qpw(x))i+1.....⊕H(Qpw(x))n
#generate a secret M_ = Qq(x), Hnew, ts1

import time
import random
from chebyshev import chebyshev, int_to_bytes, xor
from Crypto.Hash import SHA256
with open('hpassword.txt','r') as pw:
    hpw = pw.readlines()
    for i in range(len(hpw)):
        hpw[i] = int(hpw[i][:-2])
with open('ga_msg.txt', 'r') as msg:
    ga_msg = msg.readlines()
    for i in range(len(ga_msg)):
        ga_msg[i] = int(ga_msg[i][:-2])
#print(ga_msg)
hQpw = []
for i in range(len(hpw)):
    hpw[i] = int_to_bytes(hpw[i])
    ga_msg[i] = int_to_bytes(ga_msg[i])
    hQpw.append(xor(hpw[i], ga_msg[i]))
#print(hQpw)
#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, t = int(lines[0]), int(lines[1]), int(lines[2])
#generate Qq(x) with a random number q
q = random.randint(10**3, 10**5)
Qq = chebyshev(q, x, p)
Hnew = hQpw[0]
for i in range(1,len(hQpw)):
     Hnew = xor(Hnew,hQpw[i])
#print(Hnew)
#generate a secret M_ = Qq(x), Hnew, ts1
ts1 = int(time.time())
M_fs2 = int_to_bytes(Qq) + Hnew + int_to_bytes(ts1)
hM_fs2 = SHA256.new(M_fs2).digest()
with open('ssk_fs2.txt','w') as fs2:
     fs2.writelines([str(int.from_bytes(M_fs2)),str(int.from_bytes(hM_fs2))])