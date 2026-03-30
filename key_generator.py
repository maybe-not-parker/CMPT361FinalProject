from Crypto.PublicKey import RSA
import os

def generate_keys(name):
       if os.path.exists(f"{name}_private.pem") or os.path.exists(f"{name}_public.pem"):
              return
       
       key = RSA.generate(2048)
       
       private_key = key.export_key()
       public_key = key.publickey().export_key()
       
       with open(f"{name}_private.pem", "wb") as file:
              file.write(private_key)
              
       with open(f"{name}_public.pem", "wb") as file:
              file.write(public_key)
              
def main():
    generate_keys("server")
    generate_keys("client1")
    generate_keys("client2")
    generate_keys("client3")
    generate_keys("client4")
    generate_keys("client5")
