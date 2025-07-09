# 🦴 RRRRRRLWE — Molecon Finals 2023

This challenge is lost to time, but it was also the **first crypto challenge I ever wrote**. That means I care about it, even if it’s sooo baaad xD, and I think it deserves a place in this repo.

It’s a reminder of a different time, when every small step forward in cryptography felt like an amazing achievement, and all the people in the crypto scene still felt so big and unreachable.


# crypto - RRRRRRLWE
*Challenge*
* Author: Sant
* Solves: Literally everyone
* Points: Idk, 50? Is it possible to be worth less?

#### Challenge details
I found the old notebook where I wrote some ideas for this challenge and nothing else. I put that one in this repo.

It is literally RLWE but on a ring that is not commonly used (for a reason). 

````python
#===== Ring setup =======
n=2^9 #ring dim
qc=2^22 #ctx mod
qm=2^8 #ptx mod
P=PolynomialRing(Integers(qc),'x')
x=P.gen()
Pq=P.quotient(x^n-1,'y')
y=Pq.gen()


#====== RLWE =======
def gen_RLWE(m,s):
    a=Pq.random_element()
    mask= Pq.random_element()*(y-1)
    e=sum([y^i*(randint(0,2^4)-2^3) for i in range(n)])
    b=s*a+m+mask+qm*e
    return(b,a)

````

#### 🧠 Intended Solve 

The vulnerability lies in the structure of the ring and the way the mask is constructed. Since the mask is always a multiple of \((x - 1)\), evaluating the ciphertext at \(x = 1\) cancels it entirely.

This reduces each RLWE sample to a noisy scalar LWE instance:
\[
b(1) = a(1) \cdot s(1) + m + \text{small noise} \mod q_c
\]

By brute-forcing \(s(1)\) over \(\mathbb{Z}_{q_c}\) and checking which value makes all the residuals small across a block of 6 ciphertexts, we can recover the plaintext bytes. Repeating this process reconstructs the entire flag.

### Comments, three years later

Probably there are a lot of many other ways to solve this. I don't even remember if I was able to actually select parameters that were secure against common lattice attacks. I am sure that I at least tried xD
Thanks to Matteo Rossi for not judging me for this challenge, and for supporting me during all these years 💙. 
