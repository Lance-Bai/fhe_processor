from estimator import *
from estimator import LWE

q = 2**64
cores_num = 8  

tests = [
    (710, 2.8147e14),
    (2048, 8192),
]

ATTACKS = [
    ("usvp",  LWE.primal_usvp),   
    ("bdd",   LWE.primal_bdd),    
    ("dual",  LWE.dual),          
]

for n, sigma in tests:
    params = LWE.Parameters(n=n, q=q, Xs=ND.Uniform(0, 1),
                            Xe=ND.DiscreteGaussian(sigma), m=2*n)
    print(f"\n== n={n}, q={q}, sigma={sigma} ==")
    for name, fn in ATTACKS:
        res = fn(params)  
        print(f"{name:8s} :: {res}")
    print()