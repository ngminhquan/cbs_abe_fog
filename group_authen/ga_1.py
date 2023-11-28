import random
import time
import math
from chebyshev import chebyshev, int_to_bytes
from Crypto.Hash import SHA256
#Group Admin Authentication: This section initially 
# looked at the process for group admin (GA) authentication at FS 
# before moving on to distributed multiparty keying

#GA(group admin)                            FS(Fog server)
'''
Random number r
Compute Qr(x) (chebyshev)
GA_h = H(GA_id, Qr(x))
GA_msg = GA_ts+GA_h+Qr(x)+GA_id

            --------E(GA_msg,FSpu)|H(GA_msg)---->

                                            GA_msg = D(GA_msg, FSpk)
                                            ts-GA_ts <= t?
                                            GA_h == GA_h_new?

                                            Random number s
                                            FS_msg = FS_id,H(FS_id),Qs(x)
            <-------FS_msg, H(FS_msg, Qr(x))----
Check H(FS_msg',Qr(x)) == H(FS_msg, Qr(x))?
Compute Qrs(x) = Qr(Qs(x))
GA_msg2 = GA_id+Qrs(x)
            --------GA_msg2, H(GA_msg2, Qrs(x))--->
                                            Verify msg2
                                            if Qrs(x) == Qsr(x):
                                                Session authenticated
                                            else:
                                                FS reject the session
'''

#generate random large prime number with order length
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    for i in range(5, int(math.sqrt(n)) + 1, 6):
        if n % i == 0 or n % (i + 2) == 0:
            return False
    return True
def generate_random_prime(length):
    while True:
        num = random.getrandbits(length)
        if is_prime(num):
            return num
        
#generate x & p for chebyshev
#t is delay between submission and reception
x = random.randint(10**3, 10**4)
p = generate_random_prime(32)
t = 300
#Save parameters for chebyshev and public key, cert of RC
with open('cbs_para.txt','w',encoding='utf-8') as para:
    para.writelines([str(x),'\n',str(p),'\n',str(t)])
#Random r and compute Qr(x)
r = random.randint(10**3, 10**5)
Qr = chebyshev(r, x, p)
#GA_h = H(GA_id, Qr(x))
#GA_msg = GA_ts+GA_h+Qr(x)+GA_id
#GA enter its id
GA_id = input("Enter GA's id: ").encode('utf-8')
GA_h = SHA256.new(GA_id + int_to_bytes(Qr)).digest()

#message send to FS
#GA_msg = GA_ts+GA_h+Qr(x)+GA_id
GA_ts = str(int(time.time()))
GA_h = str(int.from_bytes(GA_h))
Qr = str(Qr)
GA_id = str(int.from_bytes(GA_id))
lines = [GA_ts,'\n', GA_h,'\n', Qr,'\n', GA_id]
with open('ga_auth_1.txt', 'w') as auth1:
    auth1.writelines(lines)

#Save ga's data
with open('ga_data.txt', 'w') as ga:
    ga.writelines([GA_id, '\n',str(r),'\n', str(Qr)])