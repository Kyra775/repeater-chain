def rotate_ip():
    new_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
    node.set_ip(new_ip)
