import random

headers = [
    "src_ip","dst_ip","src_port","dst_port","protocol","timestamp",
    "flow_duration","flow_byts_s","flow_pkts_s","fwd_pkts_s","bwd_pkts_s",
    "tot_fwd_pkts","tot_bwd_pkts","totlen_fwd_pkts","totlen_bwd_pkts",
    "fwd_pkt_len_max","fwd_pkt_len_min","fwd_pkt_len_mean","fwd_pkt_len_std",
    "bwd_pkt_len_max","bwd_pkt_len_min","bwd_pkt_len_mean","bwd_pkt_len_std",
    "pkt_len_max","pkt_len_min","pkt_len_mean","pkt_len_std","pkt_len_var",
    "fwd_header_len","bwd_header_len","fwd_seg_size_min","fwd_act_data_pkts",
    "flow_iat_mean","flow_iat_max","flow_iat_min","flow_iat_std",
    "fwd_iat_tot","fwd_iat_max","fwd_iat_min","fwd_iat_mean","fwd_iat_std",
    "bwd_iat_tot","bwd_iat_max","bwd_iat_min","bwd_iat_mean","bwd_iat_std",
    "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
    "fin_flag_cnt","syn_flag_cnt","rst_flag_cnt","psh_flag_cnt","ack_flag_cnt",
    "urg_flag_cnt","ece_flag_cnt","down_up_ratio","pkt_size_avg",
    "init_fwd_win_byts","init_bwd_win_byts",
    "active_max","active_min","active_mean","active_std",
    "idle_max","idle_min","idle_mean","idle_std",
    "fwd_byts_b_avg","fwd_pkts_b_avg","bwd_byts_b_avg","bwd_pkts_b_avg",
    "fwd_blk_rate_avg","bwd_blk_rate_avg",
    "fwd_seg_size_avg","bwd_seg_size_avg",
    "cwr_flag_count",
    "subflow_fwd_pkts","subflow_bwd_pkts","subflow_fwd_byts","subflow_bwd_byts"
]

def random_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return random.randint(1024, 65535)

def get_synthetic_flows():

    flows = []

    def add(label, base, n):
        for _ in range(n):

            flow = {feature: 0 for feature in headers}
            
            flow["src_ip"] = random_ip()
            flow["dst_ip"] = "192.168.0.1"
            flow["src_port"] = random_port()

            for k, v in base.items():
                flow[k] = v() if callable(v) else v

            flows.append((label, flow))

    

    # 1. Dead Service
   
    add("Dead Service", {
        "dst_port": lambda: random.randint(8000, 9000),
        "rst_flag_cnt": lambda: random.randint(2, 4),
        "flow_pkts_s": lambda: random.uniform(1.0, 5.0),
        "pkt_size_avg": 0,
        "fwd_pkts_s": lambda: random.randint(1, 5),
        "bwd_pkt_len_std": 0,
        "flow_iat_max": lambda: random.randint(100, 500),
        "ack_flag_cnt": 0,
        "syn_flag_cnt": 1,
        "pkt_len_max": 0,
        "pkt_len_std": 0
    }, 5)

    # 2. TCP Handshake Anomaly
   
    add("TCP Handshake Anomaly", {
        "dst_port": lambda: random.choice([8081, 9000, 3000, 5000]),
        "syn_flag_cnt": lambda: random.randint(3, 6),
        "ack_flag_cnt": 0,
        "rst_flag_cnt": 0,
        "flow_pkts_s": lambda: random.randint(10, 50),
        "pkt_size_avg": lambda: random.randint(20, 60),
        "fwd_pkts_s": lambda: random.randint(10, 50),
        "bwd_pkt_len_std": 0,
        "flow_iat_max": lambda: random.randint(500, 2000),
        "pkt_len_max": 64,
        "pkt_len_std": 0
    }, 5)

    # 3. Keep Alive Timeout
    
    add("Keep Alive Timeout", {
        "dst_port": lambda: random.choice([80, 443]),
        "flow_iat_max": lambda: random.randint(61000000, 75000000),
        "flow_pkts_s": lambda: random.uniform(0.1, 1.5),
        "syn_flag_cnt": 1,
        "ack_flag_cnt": lambda: random.randint(1, 3),
        "rst_flag_cnt": 0,
        "pkt_size_avg": lambda: random.randint(40, 100),
        "fwd_pkts_s": lambda: random.randint(1, 5),
        "bwd_pkt_len_std": lambda: random.randint(5, 20),
        "pkt_len_max": 128,
        "pkt_len_std": lambda: random.randint(5, 15)
    }, 5)

    # 4. Packet Size Anomaly
    
    add("Packet Size Anomaly", {
        "dst_port": lambda: random.choice([80, 443, 8080]),
        "pkt_len_max": lambda: random.randint(1600, 3500),
        "pkt_len_std": lambda: random.randint(550, 1200),
        "rst_flag_cnt": 0,
        "flow_pkts_s": lambda: random.randint(20, 100),
        "syn_flag_cnt": 1,
        "ack_flag_cnt": lambda: random.randint(10, 50),
        "pkt_size_avg": lambda: random.randint(1000, 1400),
        "fwd_pkts_s": lambda: random.randint(10, 50),
        "bwd_pkt_len_std": lambda: random.randint(400, 800),
        "flow_iat_max": lambda: random.randint(1000, 5000)
    }, 5)

   

    # FTP ATTACKS

    add("FTP-Patator", {
        "dst_port": 21,
        "pkt_size_avg": lambda: random.randint(40, 80),
        "fwd_pkts_s": lambda: random.randint(4000, 9000),
        "bwd_pkt_len_std": lambda: random.randint(40, 120),
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_cnt": lambda: random.randint(100, 300),
        "syn_flag_cnt": lambda: random.randint(4, 10),
        "rst_flag_cnt": 1
    }, 8)

    add("FTP-Patator - Attempted", {
        "dst_port": 21,
        "pkt_size_avg": lambda: random.randint(0, 4),
        "fwd_pkts_s": lambda: random.randint(300, 1500),
        "bwd_pkt_len_std": lambda: random.randint(10, 70),
        "flow_iat_max": lambda: random.randint(300, 1000),
        "ack_flag_cnt": lambda: random.randint(10, 80),
        "syn_flag_cnt": lambda: random.randint(1, 3),
        "rst_flag_cnt": 1
    }, 5)

    # SSH ATTACKS

    add("SSH-Patator", {
        "dst_port": 22,
        "pkt_size_avg": lambda: random.randint(30, 80),
        "fwd_pkts_s": lambda: random.randint(3500, 8500),
        "bwd_pkt_len_std": lambda: random.randint(40, 120),
        "flow_iat_max": lambda: random.randint(50, 300),
        "ack_flag_cnt": lambda: random.randint(100, 300),
        "syn_flag_cnt": lambda: random.randint(5, 12),
        "rst_flag_cnt": 1
    }, 8)

    add("SSH-Patator - Attempted", {
        "dst_port": 22,
        "pkt_size_avg": lambda: random.randint(0, 4),
        "fwd_pkts_s": lambda: random.randint(300, 1500),
        "bwd_pkt_len_std": lambda: random.randint(10, 70),
        "flow_iat_max": lambda: random.randint(400, 1200),
        "ack_flag_cnt": lambda: random.randint(10, 80),
        "syn_flag_cnt": lambda: random.randint(1, 4),
        "rst_flag_cnt": 1
    }, 5)

    add("DoS Hulk", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(800, 1200),
        "fwd_pkts_s": lambda: random.randint(5000, 12000),
        "bwd_pkt_len_std": lambda: random.randint(3000, 6000),
        "flow_iat_max": lambda: random.randint(10, 150),
        "ack_flag_cnt": lambda: random.randint(4000, 9000),
        "syn_flag_cnt": lambda: random.randint(20, 50),
        "rst_flag_cnt": 0
    }, 10)

    add("DoS Hulk - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(400, 700),
        "fwd_pkts_s": lambda: random.randint(800, 3000),
        "bwd_pkt_len_std": lambda: random.randint(1000, 2500),
        "flow_iat_max": lambda: random.randint(300, 1500),
        "ack_flag_cnt": lambda: random.randint(800, 2500),
        "syn_flag_cnt": lambda: random.randint(5, 15),
        "rst_flag_cnt": 0
    }, 5)

    add("DoS GoldenEye", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(700, 1000),
        "fwd_pkts_s": lambda: random.randint(3000, 7000),
        "bwd_pkt_len_std": lambda: random.randint(2000, 4000),
        "flow_iat_max": lambda: random.randint(100, 800),
        "ack_flag_cnt": lambda: random.randint(2000, 5000),
        "syn_flag_cnt": lambda: random.randint(10, 30),
        "rst_flag_cnt": 0
    }, 10)

    add("DoS GoldenEye - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(400, 700),
        "fwd_pkts_s": lambda: random.randint(800, 2500),
        "bwd_pkt_len_std": lambda: random.randint(800, 2000),
        "flow_iat_max": lambda: random.randint(400, 1500),
        "ack_flag_cnt": lambda: random.randint(800, 2000),
        "syn_flag_cnt": lambda: random.randint(3, 10),
        "rst_flag_cnt": 0
    }, 5)

    # SLOW ATTACKS

    add("DoS Slowloris", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(150, 350),
        "fwd_pkts_s": lambda: random.randint(10, 100),
        "bwd_pkt_len_std": lambda: random.randint(200, 800),
        "flow_iat_max": lambda: random.randint(10000, 30000),
        "ack_flag_cnt": lambda: random.randint(200, 600),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0
    }, 5)

    add("DoS Slowloris - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(50, 150),
        "fwd_pkts_s": lambda: random.randint(10, 60),
        "bwd_pkt_len_std": lambda: random.randint(100, 400),
        "flow_iat_max": lambda: random.randint(5000, 15000),
        "ack_flag_cnt": lambda: random.randint(50, 200),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0
    }, 5)

    add("DoS Slowhttptest", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(150, 400),
        "fwd_pkts_s": lambda: random.randint(50, 250),
        "bwd_pkt_len_std": lambda: random.randint(300, 1000),
        "flow_iat_max": lambda: random.randint(10000, 30000),
        "ack_flag_cnt": lambda: random.randint(300, 800),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0
    }, 5)

    add("DoS Slowhttptest - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(50, 200),
        "fwd_pkts_s": lambda: random.randint(20, 120),
        "bwd_pkt_len_std": lambda: random.randint(100, 500),
        "flow_iat_max": lambda: random.randint(5000, 15000),
        "ack_flag_cnt": lambda: random.randint(100, 300),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0
    }, 5)

    add("Portscan", {
        "protocol": lambda: random.choices([6, 17, 1], weights=[80, 15, 5])[0],
        "dst_port": lambda: random.choice([4444, 5555, 6666]),
        "pkt_size_avg": lambda: random.randint(1, 5),
        "fwd_pkts_s": lambda: random.randint(12000, 20000),
        "bwd_pkt_len_std": 0,
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_cnt": 0,
        "syn_flag_cnt": lambda: random.choice([1, 3, 4, 5]),
        "rst_flag_cnt": 0
    }, 6)

    # INFILTRATION 

    add("Infiltration", {
        "protocol": lambda: random.choices([6, 17], weights=[90, 10])[0],
        "dst_port": lambda: random.choice([4444, 5555, 6666]),
        "pkt_size_avg": lambda: random.randint(100, 300),
        "fwd_pkts_s": lambda: random.randint(50, 300),
        "bwd_pkt_len_std": 0,
        "flow_iat_max": lambda: random.randint(21000000, 35000000),
        "ack_flag_cnt": lambda: random.randint(300, 800),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 8)

    add("Infiltration - Attempted", {
        "dst_port": lambda: random.choice([4444, 5555, 6666]),
        "pkt_size_avg": lambda: random.randint(0, 4),       
        "fwd_pkts_s": lambda: random.randint(250, 1000),    
        "bwd_pkt_len_std": lambda: random.randint(400, 1200),
        "flow_iat_max": lambda: random.randint(3000, 15000),
        "ack_flag_cnt": lambda: random.randint(150, 500),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": lambda: random.randint(1, 3)
    }, 5)


    add("Infiltration - Portscan", {
        "dst_port": lambda: random.choice([21, 22, 23, 80, 8080]),
        "pkt_size_avg": lambda: random.randint(0, 4),       
        "fwd_pkts_s": lambda: random.randint(10001, 20000),
        "bwd_pkt_len_std": 0,
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_cnt": 0,
        "syn_flag_cnt": 2,
        "rst_flag_cnt": 0
    }, 6)


    # BOTNET

    add("Botnet", {
        "dst_port": 8080,
        "pkt_size_avg": lambda: random.randint(100, 300),
        "fwd_pkts_s": lambda: random.randint(500, 3000),
        "bwd_pkt_len_std": lambda: random.randint(300, 1200),
        "flow_iat_max": lambda: random.randint(1000, 8000),
        "ack_flag_cnt": lambda: random.randint(100, 400),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 8)

    add("Botnet - Attempted", {
        "dst_port": 8080,
        "pkt_size_avg": lambda: random.randint(0, 4),
        "fwd_pkts_s": lambda: random.randint(100, 800),
        "bwd_pkt_len_std": lambda: random.randint(100, 500),
        "flow_iat_max": lambda: random.randint(500, 5000),
        "ack_flag_cnt": lambda: random.randint(50, 200),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)


    # WEB ATTACKS

    add("Web Attack - Brute Force", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(50, 200),
        "fwd_pkts_s": lambda: random.randint(500, 3000),
        "bwd_pkt_len_std": lambda: random.randint(50, 300),
        "flow_iat_max": lambda: random.randint(500, 3000),
        "ack_flag_cnt": lambda: random.randint(100, 400),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)

    add("Web Attack - Brute Force - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(30, 150),
        "fwd_pkts_s": lambda: random.randint(200, 1500),
        "bwd_pkt_len_std": lambda: random.randint(30, 200),
        "flow_iat_max": lambda: random.randint(300, 2000),
        "ack_flag_cnt": lambda: random.randint(50, 200),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)

    add("Web Attack - XSS", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(100, 300),
        "fwd_pkts_s": lambda: random.randint(500, 2000),
        "bwd_pkt_len_std": lambda: random.randint(100, 400),
        "flow_iat_max": lambda: random.randint(1000, 5000),
        "ack_flag_cnt": lambda: random.randint(100, 400),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)

    add("Web Attack - XSS - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(50, 200),
        "fwd_pkts_s": lambda: random.randint(200, 1000),
        "bwd_pkt_len_std": lambda: random.randint(50, 300),
        "flow_iat_max": lambda: random.randint(500, 3000),
        "ack_flag_cnt": lambda: random.randint(50, 200),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)

    add("Web Attack - SQL Injection", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(100, 400),
        "fwd_pkts_s": lambda: random.randint(500, 2000),
        "bwd_pkt_len_std": lambda: random.randint(100, 500),
        "flow_iat_max": lambda: random.randint(1000, 5000),
        "ack_flag_cnt": lambda: random.randint(100, 400),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)

    add("Web Attack - SQL Injection - Attempted", {
        "dst_port": 80,
        "pkt_size_avg": lambda: random.randint(50, 250),
        "fwd_pkts_s": lambda: random.randint(200, 1500),
        "bwd_pkt_len_std": lambda: random.randint(50, 300),
        "flow_iat_max": lambda: random.randint(500, 3000),
        "ack_flag_cnt": lambda: random.randint(50, 200),
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 1
    }, 5)

    # HEARTBLEED
  
    add("Heartbleed", {
        "dst_port": 443,
        "pkt_size_avg": lambda: random.randint(1500, 2000),
        "fwd_pkts_s": lambda: random.randint(5, 20),
        "bwd_pkt_len_std": lambda: random.randint(3000, 6000),
        "flow_iat_max": lambda: random.randint(50, 200),
        "ack_flag_cnt": lambda: random.randint(3000, 8000),
        "syn_flag_cnt": 0,
        "rst_flag_cnt": 0
    }, 8)

    return flows