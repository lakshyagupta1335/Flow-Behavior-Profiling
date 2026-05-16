import random

def random_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return random.randint(1024, 65535)

def get_synthetic_flows():

    flows = []

    def add(label, base, n):
        for _ in range(n):
            
            flows.append((
                label,
                {
                    "src_ip": random_ip(),
                    "dst_ip": "192.168.0.1",
                    "src_port": random_port(),
                    **{k: (v() if callable(v) else v) for k, v in base.items()}
                }
            ))

    # FTP ATTACKS

    add("FTP-Patator", {
        "dst_port": 21,
        "avg_packet_size": lambda: random.randint(40, 80),
        "fwd_packets_s": lambda: random.randint(4000, 9000),
        "bwd_packet_length_std": lambda: random.randint(40, 120),
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_count": lambda: random.randint(100, 300),
        "syn_flag_count": lambda: random.randint(4, 10),
        "rst_flag_count": 1
    }, 8)

    add("FTP-Patator - Attempted", {
        "dst_port": 21,
        "avg_packet_size": lambda: random.randint(10, 40),
        "fwd_packets_s": lambda: random.randint(300, 1500),
        "bwd_packet_length_std": lambda: random.randint(10, 70),
        "flow_iat_max": lambda: random.randint(300, 1000),
        "ack_flag_count": lambda: random.randint(10, 80),
        "syn_flag_count": lambda: random.randint(1, 3),
        "rst_flag_count": 1
    }, 5)


    # SSH ATTACKS

    add("SSH-Patator", {
        "dst_port": 22,
        "avg_packet_size": lambda: random.randint(30, 80),
        "fwd_packets_s": lambda: random.randint(3500, 8500),
        "bwd_packet_length_std": lambda: random.randint(40, 120),
        "flow_iat_max": lambda: random.randint(50, 300),
        "ack_flag_count": lambda: random.randint(100, 300),
        "syn_flag_count": lambda: random.randint(5, 12),
        "rst_flag_count": 1
    }, 8)

    add("SSH-Patator - Attempted", {
        "dst_port": 22,
        "avg_packet_size": lambda: random.randint(10, 35),
        "fwd_packets_s": lambda: random.randint(300, 1500),
        "bwd_packet_length_std": lambda: random.randint(10, 70),
        "flow_iat_max": lambda: random.randint(400, 1200),
        "ack_flag_count": lambda: random.randint(10, 80),
        "syn_flag_count": lambda: random.randint(1, 4),
        "rst_flag_count": 1
    }, 5)


    # DOS ATTACKS

    add("DoS Hulk", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(800, 1200),
        "fwd_packets_s": lambda: random.randint(5000, 12000),
        "bwd_packet_length_std": lambda: random.randint(3000, 6000),
        "flow_iat_max": lambda: random.randint(10, 150),
        "ack_flag_count": lambda: random.randint(4000, 9000),
        "syn_flag_count": lambda: random.randint(20, 50),
        "rst_flag_count": 0
    }, 10)

    add("DoS Hulk - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(400, 700),
        "fwd_packets_s": lambda: random.randint(800, 3000),
        "bwd_packet_length_std": lambda: random.randint(1000, 2500),
        "flow_iat_max": lambda: random.randint(300, 1500),
        "ack_flag_count": lambda: random.randint(800, 2500),
        "syn_flag_count": lambda: random.randint(5, 15),
        "rst_flag_count": 0
    }, 5)

    add("DoS GoldenEye", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(700, 1000),
        "fwd_packets_s": lambda: random.randint(3000, 7000),
        "bwd_packet_length_std": lambda: random.randint(2000, 4000),
        "flow_iat_max": lambda: random.randint(100, 800),
        "ack_flag_count": lambda: random.randint(2000, 5000),
        "syn_flag_count": lambda: random.randint(10, 30),
        "rst_flag_count": 0
    }, 10)

    add("DoS GoldenEye - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(400, 700),
        "fwd_packets_s": lambda: random.randint(800, 2500),
        "bwd_packet_length_std": lambda: random.randint(800, 2000),
        "flow_iat_max": lambda: random.randint(400, 1500),
        "ack_flag_count": lambda: random.randint(800, 2000),
        "syn_flag_count": lambda: random.randint(3, 10),
        "rst_flag_count": 0
    }, 5)


    # SLOW ATTACKS

    add("DoS Slowloris", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(150, 350),
        "fwd_packets_s": lambda: random.randint(10, 100),
        "bwd_packet_length_std": lambda: random.randint(200, 800),
        "flow_iat_max": lambda: random.randint(10000, 30000),
        "ack_flag_count": lambda: random.randint(200, 600),
        "syn_flag_count": 1,
        "rst_flag_count": 0
    }, 5)

    add("DoS Slowloris - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(50, 150),
        "fwd_packets_s": lambda: random.randint(10, 60),
        "bwd_packet_length_std": lambda: random.randint(100, 400),
        "flow_iat_max": lambda: random.randint(5000, 15000),
        "ack_flag_count": lambda: random.randint(50, 200),
        "syn_flag_count": 1,
        "rst_flag_count": 0
    }, 5)

    add("DoS Slowhttptest", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(150, 400),
        "fwd_packets_s": lambda: random.randint(50, 250),
        "bwd_packet_length_std": lambda: random.randint(300, 1000),
        "flow_iat_max": lambda: random.randint(10000, 30000),
        "ack_flag_count": lambda: random.randint(300, 800),
        "syn_flag_count": 1,
        "rst_flag_count": 0
    }, 5)

    add("DoS Slowhttptest - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(50, 200),
        "fwd_packets_s": lambda: random.randint(20, 120),
        "bwd_packet_length_std": lambda: random.randint(100, 500),
        "flow_iat_max": lambda: random.randint(5000, 15000),
        "ack_flag_count": lambda: random.randint(100, 300),
        "syn_flag_count": 1,
        "rst_flag_count": 0
    }, 5)


    # INFILTRATION 

    add("Infiltration", {
        "dst_port": lambda: random.choice([4444, 5555, 6666]),
        "avg_packet_size": lambda: random.randint(300, 800),
        "fwd_packets_s": lambda: random.randint(50, 300),
        "bwd_packet_length_std": lambda: random.randint(800, 2000),
        "flow_iat_max": lambda: random.randint(5000, 20000),
        "ack_flag_count": lambda: random.randint(300, 800),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 8)

    add("Infiltration - Attempted", {
        "dst_port": lambda: random.choice([4444, 5555, 6666]),
        "avg_packet_size": lambda: random.randint(200, 600),
        "fwd_packets_s": lambda: random.randint(20, 150),
        "bwd_packet_length_std": lambda: random.randint(400, 1200),
        "flow_iat_max": lambda: random.randint(3000, 15000),
        "ack_flag_count": lambda: random.randint(150, 500),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    add("Infiltration - Portscan", {
        "dst_port": lambda: random.choice([21, 22, 23, 80, 8080]),
        "avg_packet_size": lambda: random.randint(1, 10),
        "fwd_packets_s": lambda: random.randint(8000, 20000),
        "bwd_packet_length_std": 0,
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_count": 0,
        "syn_flag_count": lambda: random.randint(1, 3),
        "rst_flag_count": 0
    }, 6)

    # BOTNET

    add("Botnet", {
        "dst_port": 8080,
        "avg_packet_size": lambda: random.randint(100, 300),
        "fwd_packets_s": lambda: random.randint(500, 3000),
        "bwd_packet_length_std": lambda: random.randint(300, 1200),
        "flow_iat_max": lambda: random.randint(1000, 8000),
        "ack_flag_count": lambda: random.randint(100, 400),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 8)

    add("Botnet - Attempted", {
        "dst_port": 8080,
        "avg_packet_size": lambda: random.randint(50, 200),
        "fwd_packets_s": lambda: random.randint(100, 800),
        "bwd_packet_length_std": lambda: random.randint(100, 500),
        "flow_iat_max": lambda: random.randint(500, 5000),
        "ack_flag_count": lambda: random.randint(50, 200),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    # WEB ATTACKS

    add("Web Attack - Brute Force", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(50, 200),
        "fwd_packets_s": lambda: random.randint(500, 3000),
        "bwd_packet_length_std": lambda: random.randint(50, 300),
        "flow_iat_max": lambda: random.randint(500, 3000),
        "ack_flag_count": lambda: random.randint(100, 400),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    add("Web Attack - Brute Force - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(30, 150),
        "fwd_packets_s": lambda: random.randint(200, 1500),
        "bwd_packet_length_std": lambda: random.randint(30, 200),
        "flow_iat_max": lambda: random.randint(300, 2000),
        "ack_flag_count": lambda: random.randint(50, 200),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    add("Web Attack - XSS", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(100, 300),
        "fwd_packets_s": lambda: random.randint(500, 2000),
        "bwd_packet_length_std": lambda: random.randint(100, 400),
        "flow_iat_max": lambda: random.randint(1000, 5000),
        "ack_flag_count": lambda: random.randint(100, 400),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    add("Web Attack - XSS - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(50, 200),
        "fwd_packets_s": lambda: random.randint(200, 1000),
        "bwd_packet_length_std": lambda: random.randint(50, 300),
        "flow_iat_max": lambda: random.randint(500, 3000),
        "ack_flag_count": lambda: random.randint(50, 200),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    add("Web Attack - SQL Injection", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(100, 400),
        "fwd_packets_s": lambda: random.randint(500, 2000),
        "bwd_packet_length_std": lambda: random.randint(100, 500),
        "flow_iat_max": lambda: random.randint(1000, 5000),
        "ack_flag_count": lambda: random.randint(100, 400),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)

    add("Web Attack - SQL Injection - Attempted", {
        "dst_port": 80,
        "avg_packet_size": lambda: random.randint(50, 250),
        "fwd_packets_s": lambda: random.randint(200, 1500),
        "bwd_packet_length_std": lambda: random.randint(50, 300),
        "flow_iat_max": lambda: random.randint(500, 3000),
        "ack_flag_count": lambda: random.randint(50, 200),
        "syn_flag_count": 1,
        "rst_flag_count": 1
    }, 5)


    # HEARTBLEED
  
    add("Heartbleed", {
        "dst_port": 443,
        "avg_packet_size": lambda: random.randint(1500, 2000),
        "fwd_packets_s": lambda: random.randint(5, 20),
        "bwd_packet_length_std": lambda: random.randint(3000, 6000),
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_count": lambda: random.randint(3000, 8000),
        "syn_flag_count": 0,
        "rst_flag_count": 0
    }, 8)

    return flows




