import math
import time

from passlib.hash import argon2
import threading
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')


key = "0000da975bd6ec3aa878dadc395943619d23407371bc15066c1505ef23203d871633c687a9e5e89f5fc7fb61f05e1ff4ec49ecee28577c5143711185afe2d5a5".encode()  # Replace with your actual key
m_value = 262144
t_value = 1
p_value = 1
salt_bytes = b"XEN10082022XEN"
loop = 0

argon2_hasher = argon2.using(time_cost=t_value, memory_cost=m_value, parallelism=p_value, salt=salt_bytes, hash_len=64)


def run():
    global loop
    while True:
        hash = argon2_hasher.hash(key)
        # logging.debug(hash)
        loop += 1


threading.Thread(target=run).start()
while True:
    time.sleep(10)
    logging.info("tps=%d memory=%d", math.floor(loop / 10), argon2_hasher.memory_cost)
    # argon2_hasher.memory_cost += 1024
    loop = 0
