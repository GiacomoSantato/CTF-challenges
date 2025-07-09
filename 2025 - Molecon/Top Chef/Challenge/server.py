from sage.all import *
from random import randint
import hashlib
import json

class Curve_Setup:
    def __init__(self):
        self.p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45
        self.K = GF(self.p)
        
        self.A = self.K(0x081806)
        self.B = self.K(0x01)
        self.E = EllipticCurve(self.K, ((3 - self.A**2)/(3 * self.B**2), (2 * self.A**3 - 9 * self.A)/(27 * self.B**3)))
        
        def to_weierstrass(A, B, x, y):
            return (x/B + A/(3*B), y/B)
        
        def to_montgomery(A, B, u, v):
            return (B * (u - A/(3*B)), B*v)
        

        self.G = self.E(*to_weierstrass(self.A, self.B, self.K(0x05), self.K(0x2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5)))
        self.E.set_order(0x100000000000000000000000000000000000000000000000000000000000000017B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B * 0x08)
        self.q = self.G.order()
        assert self.E.order()%self.q==0
        
        
class Challenge:
    def __init__(self):
        self.S = Curve_Setup()
        self.q = self.S.q
        self.G = self.S.G
        
        self.N = 5
        self.MAX_DAILY_DISHES= 376
        self.CURRENT_DISH_NUMBER=0

        self.sk= [randint(1,self.q) for _ in range(self.N)]
        self.SK= sum(self.sk) % self.q

        self.pk = [ sk_i*self.G for sk_i in self.sk]
        self.PK = sum(self.pk)
        
        self.t={}
        self.T={}
        self.dishes={}
        self.closed=[]

        
        self.FLAG= "PTM{H4v3_y0u_3v3r_tr13d_4rROSt1c1n1?}"
#        self.FLAG= "PTM{????????????????????????????????}"

        self.before_input = ["Welcome to the Top Italian Chef Academy!",
                             "Our role is to certify which are the best dishes you can taste in Turin.",
                             "Every member can suggest new dishes whenever they want.",
                             "If the others agree, they sign it as a new dish.",
                             "If you get all the signatures, you can add the dish to the list.",
                             "We hope that, as our newest member, you will help us in our mission ^.^",
                             f"Your secret key as a new member is:{self.sk[0]}",
                             f"The public keys of the members are:{self.pk}" ]


    def challenge(self, your_input):

        def random_oracle(R,m):
            to_hash=str(self.G.xy()[0])+str(self.PK.xy()[0])+str(R.xy()[0])+m
            hash=hashlib.blake2b(to_hash.encode()).digest()
            for _ in range(10000): hash=hashlib.blake2b(hash).digest()
            return int.from_bytes(hash,"big")
        
        def verify(message,signature):
            R,s=signature
            c=random_oracle(R,message)
            return self.G*s==self.PK*c+R


        if "option" not in your_input: 
            return{"msg":"Send a valid option."}
        
        if your_input["option"] == "suggest_new_dish":
            if "dish" not in your_input:
                return {"msg":"No dish provided."}          
            if your_input["dish"] not in ["Bagna Cauda","Vitello Tonnato","Agnolotti","Agnolotti Del Plin","Fritto Misto"]:
                return {"msg":"No other member supported your suggestion"}
            if self.CURRENT_DISH_NUMBER>=self.MAX_DAILY_DISHES:
                return {"msg":"Sorry, too much work for one day. Go home and sleep."}
            
            else:
                current_t=[randint(1,self.q) for _ in range(self.N-1)]
                current_T=[t_i*self.G for t_i in current_t]
                
                self.t[self.CURRENT_DISH_NUMBER]=current_t
                self.T[self.CURRENT_DISH_NUMBER]=current_T
                self.dishes[self.CURRENT_DISH_NUMBER]=your_input["dish"]
                

                self.CURRENT_DISH_NUMBER+=1
                return{"msg":f"All the other members agree! They send you {[Pt.xy() for Pt in current_T]}"}
        

        if your_input["option"] == "sign_dish":

            if "dish_number" not in your_input :
                return {"msg":"How can we know which dish are you referring to?"}

            if your_input["dish_number"] not in self.t.keys():
                return{"msg":"Never heard about this dish"}

            if your_input["dish_number"] in self.closed:
                return{"msg": "We already signed it"}
            
            if "Tx" not in your_input or "Ty" not in your_input:
                return {"msg":"How are we suppose to sign?"}
            
            T1=[int(your_input["Tx"]),int(your_input["Ty"])]
            assert self.S.E(T1[0],T1[1])

            dish_num = int(your_input["dish_number"])
            dish = self.dishes[dish_num]
            dish_T = sum(self.T[dish_num]) + self.S.E(T1[0],T1[1])

            c = random_oracle(dish_T,dish)
            s = [ (self.t[dish_num][i] + c*self.sk[i+1])%self.q for i in range(self.N-1)]

            self.closed.append(dish_num)
            
            return{"msg":f"These are the signatures of the other members {s}"}
        
        if your_input["option"] == "publish_dish":

            if "signature_Tx" not in your_input or "signature_Ty" not in your_input or "signature_s" not in your_input or "dish" not in your_input :
                return{"msg": "To publish a decision of the academy, you need to send the dish and the signature"}
            
            assert self.S.E(your_input["signature_Tx"],your_input["signature_Ty"])
            dish_T = self.S.E(your_input["signature_Tx"],your_input["signature_Ty"])
            dish_s = your_input["signature_s"]%self.q

            if not verify(your_input["dish"],[dish_T,dish_s]):
                return{"msg": "Invalid signature! Outsiders are trying to impersonate us!"}
            
            
            else:
                if your_input["dish"] in ["Bagna Cauda","Vitello Tonnato","Agnolotti","Agnolotti Del Plin","Fritto Misto"]:
                    return{"msg": "Another successful decision for the academy!"}
                
                if your_input["dish"] == "Ananas Pizza":
                    return{"msg": f"OH NO! HOW IS THIS POSSIBLE? {self.FLAG}"}
                             
        return{"msg":"Send a valid option."}

CHAL = Challenge()
for text in CHAL.before_input: print(text)
while True:
    your_input_str=input("What do you want to do?")
    reply = CHAL.challenge(json.loads(your_input_str))
    print(json.dumps(reply))