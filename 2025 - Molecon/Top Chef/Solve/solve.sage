import hashlib
from sage.modules.free_module_integer import IntegerLattice

qCUR = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45
K = GF(qCUR)
A = K(0x081806)
B = K(0x01)
E = EllipticCurve(K, ((3 - A^2)/(3 * B^2), (2 * A^3 - 9 * A)/(27 * B^3)))
def to_weierstrass(A, B, x, y):
	return (x/B + A/(3*B), y/B)
def to_montgomery(A, B, u, v):
	return (B * (u - A/(3*B)), B*v)
G = E(*to_weierstrass(A, B, K(0x05), K(0x2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5)))
E.set_order(0x100000000000000000000000000000000000000000000000000000000000000017B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B * 0x08)
p = G.order()
Zp = GF(p)

def random_oracle(R,m):
    to_hash=str(G.xy()[0])+str(PK.xy()[0])+str(R.xy()[0])+m
    hash=hashlib.blake2b(to_hash.encode()).digest()
    for _ in range(10000): hash=hashlib.blake2b(hash).digest()
    return int.from_bytes(hash,"big")
            
def verify(message,signature):
    R,s=signature
    c=random_oracle(R,message)
    assert G*s==PK*c+R,"verification equation fails"
    return True
    
def inner_product(coefficients,values):
    return sum(y*x for x,y in zip(coefficients,values))

def scale_to_Zp(vec):
    assert all([ gcd(p,el.denominator())==1 for el in vec])
    return vector(Zp, [Zp(el.numerator())/Zp(el.denominator()) for el in vec])
    
def pows_gen( n = 7, group_bit_len=256, extra_digits=2 ):
    max_number = 2^group_bit_len
    assert n>=2
    pows=[]
    k = n-1
    while k>=1:
        #B = 2 * k^(2/3) * log(p,k+1)^(1/k) #Theorem 2 Bound
        B = 1/500
        
        max_k = ceil( log( max_number ,k+1)) 
        if k==1: e_k = 0
        else: e_k = ceil( log( B * log(p,k+1) * p^((k-1)/k) , k+1)) + extra_digits
        
        pows = [(k+1,i) for i in range(e_k,max_k)] + pows
        max_number = (k+1)^e_k
        k-=1
    return pows

def multibase(input_number, pows):
    temp_number = ZZ(input_number)
    digits=[]
    for base in pows[::-1]:
        digits=[ temp_number// base ] +digits
        temp_number = temp_number % base
    assert inner_product( digits,pows) == input_number
    return digits

#adversary: attack parameters selection
max_basis = 11
ext_dig = 1
factored_pows=pows_gen(n=max_basis+1,group_bit_len=int(p).bit_length(),extra_digits=ext_dig)

ell = 376
factored_pows=factored_pows[:ell]

pows_bases = [ i for i,j in factored_pows]
pows= [i^j for i,j in factored_pows]
ell = len(pows)
e_k = [min([factored_pows[i][1] if factored_pows[i][0]==k else 1000 for i in range(ell)]) for k in range(2,max_basis+2)]
I_k = [min([i if factored_pows[i][0]==k else 1000 for i in range(ell)]) for k in range(2,max_basis+2)] + [ell]

from pwn import *
import json
with process(["sage","server.py"]) as conn:
    for _ in range(6):    conn.recvline()
    raw = conn.recvline().decode()
    SK_atk = int(raw[35:-1])
    raw = conn.recvline().decode()[37:-3]
    raw2 = raw.split("), (")
    raw3 = [pt.split(":") for pt in raw2]
    pk = [E(int(pt[0]),int(pt[1])) for pt in raw3]
    PK = sum(pk)

    
    OPEN_SESSIONS=[]
    for _ in range(ell):
        query = {"option": "suggest_new_dish","dish": "Agnolotti"}
        conn.sendline(json.dumps(query).encode())
        raw_reply = conn.recvline()[:-1].decode()[23:]
        reply = json.loads(raw_reply)["msg"][43:]
        OPEN_SESSIONS.append(reply)

    OPEN2 = [ pts[2:-2].split("), (") for pts in OPEN_SESSIONS]
    OPEN3 = [ [ pt.split(",") for pt in pt_T] for pt_T in OPEN2]
    OPEN4 = [ [ E(int(pt[0]), int(pt[1])) for pt in pt_T] for pt_T in OPEN3]
    R = [sum(y) for y in OPEN4]

    OHNO=0
    while OHNO<4:
        OHNO+=1
        #adversary: generate challenges
        messages = ["Agnolotti" for _ in range(ell)] + ["Ananas Pizza"]
        
        alpha = [ [Zp.random_element() for _ in range(pows_bases[i])] for i in range(ell)] 
        beta = [ 0 for i in range(ell)] 
        blinded_R = [[ R[i]+G*alpha_i_b+beta[i]*PK for alpha_i_b in alpha[i]] for i in range(ell)]
        c = [ [random_oracle(blinded_R_i_b,messages[i]) for blinded_R_i_b in blinded_R[i]] for i in range(ell)]
        
        qi = [ [ c_i_b - c[i][0] for c_i_b in c[i][1:] ] for i in range(ell)]
        M = [ block_matrix([[ Matrix(ZZ,qi[i])], [p*matrix.identity(pows_bases[i]-1)]]) for i in range(ell)]

        closest_vectors = [ IntegerLattice(M[i]).babai([j*pows[i] for j in range(1,pows_bases[i])]) for i in range(ell) ]
        mu = [(1/Zp(pows[i]))*scale_to_Zp(M[i].solve_left(closest_vectors[i]))[0] for i in range(ell)]
    
        #adversary: decomposition of z
        attempts=0
        while attempts<121*2:
            attempts+=1
        
            extra_alpha = Zp.random_element()
            R_forge= extra_alpha*inner_product([i*j for i,j in zip(pows,mu)],R)
            c_to_decompose = random_oracle(R_forge, messages[ell])
            
            NUM_to_decompose = extra_alpha^(-1)*Zp(c_to_decompose) + sum([pows[i]*mu[i] * (-c[i][0]) for i in range(ell)])
            digits=[0]*ell
        
            current_digits = multibase(NUM_to_decompose,pows)
            if current_digits[-1]>=pows[-1] : break
            
            for i in range(ell)[::-1]:
                current_digits = multibase(NUM_to_decompose,pows)
                if i!=ell-1 and current_digits[i+1] != 0: break
                new_digit=current_digits[i]    
                digits[i]=new_digit
                if new_digit>=pows_bases[i]: break
                if new_digit!=0: NUM_to_decompose -= pows[i]*mu[i]*qi[i][new_digit-1] 
                if NUM_to_decompose <0: break
            if NUM_to_decompose==0: break
            if attempts>=121*2: break
        if attempts>=121*2: print("Decomposition failed, need to resample the lattices")
        else:
            adv_R = [(alpha[i][b]*G).xy() for (i,b) in enumerate(digits)]

    SIGNS=[]
    for I in range(ell):
        query = {"option": "sign_dish","dish_number": I, "Tx":int(adv_R[I][0]), "Ty": int(adv_R[I][1])}
        conn.sendline(json.dumps(query).encode())
        raw_reply = conn.recvline()[:-1].decode()[23:]
        reply = json.loads(raw_reply)["msg"][:]
        SIGNS.append(reply[47:-1].split(","))
    s = [sum([ Zp(int(s_i)) for s_i in ss]) for ss in SIGNS] 

    forged_signatures = [(blinded_R[i][digits[i]] , s[i] + c[i][digits[i]]*SK_atk  +alpha[i][digits[i]]  ) for i in range(ell)]
    s_forge = extra_alpha*inner_product([i*j for i,j in zip(pows,mu)],s)  + SK_atk* c_to_decompose
    forged_signatures += [(R_forge,  s_forge)]
    
    assert all([verify(messages[i], forged_signatures[i]) for i in range(ell+1)]) == True

    query = {"option": "publish_dish","dish":messages[ell] ,"signature_Tx":int(R_forge[0]) , "signature_Ty":int(R_forge[1]), "signature_s": int(s_forge)}
    conn.sendline(json.dumps(query).encode())
    raw_reply = conn.recvline()[:-1].decode()[23:]
    reply = json.loads(raw_reply)["msg"][29:]

    print(reply)
