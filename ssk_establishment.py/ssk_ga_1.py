#Algorithm 4: session key establishment

#GA(Group Admin)                        #FS(Fog server)
'''
There are n number of GA
each having unique password pw
∀ GA ∈ N send a message to FS
M = H(pw) ⊕ H(Qpw(x)), H(M)
            -------------M|H(M)-------->
                                        extract M ⊕ H(pw) = H(Qpw(x))
                                        generate Qq(x) with a random number q
                                        Hnew=H(Qpw(x))i⊕H(Qpw(x))i+1.....⊕H(Qpw(x))n
                                        generate a secret M_ = Qq(x), Hnew, ts1
            <-----------M_|H(M_)-------
∀GA:Hnew_ = H(GAid ⊕ Hpw ⊕ Hnew ⊕ H(Qp(Qq(x))))
∀GA send confirmation message 
M_ga2 = GAid ⊕H(pw)⊕Qp(x), Hnew_, ts2
            --------M_ga2|H(Mga_2)---->
                                        Qp(x)=GAid ⊕H(pw)⊕M_ga2
                                        Calculate H(Qp(Qq(x)))->Hnew_n
                                        FS send the confirmation message to GA
'''

import time
from Crypto.Hash import SHA256
from chebyshev import chebyshev, int_to_bytes, xor

#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, t = int(lines[0]), int(lines[1]), int(lines[2])
n = int(input('Enter number of GAs: '))
for i in range(n):
    pw = int(input('GA ' + str(i) + ' enter pw: '))
    #message sent to FS
    #M = H(pw) ⊕ H(Qpw(x))
    Qpw= chebyshev(pw,x,p)
    h_pw = SHA256.new(int_to_bytes(pw)).digest()
    h_Qpw = SHA256.new(int_to_bytes(Qpw)).digest()
    M_ga1 = xor(h_pw, h_Qpw)
    hM_ga1 = SHA256.new(M_ga1).digest()
    with open('hpassword.txt','a') as ps:
        ps.writelines([str(int.from_bytes(h_pw)),'\n'])
    with open('ga_msg.txt','a') as msg:
        msg.writelines([str(int.from_bytes(M_ga1+hM_ga1)),'\n'])