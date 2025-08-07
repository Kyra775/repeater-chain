import random

def rotate_ip(node):
    new_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    node.set_ip(new_ip)
    return new_ip
