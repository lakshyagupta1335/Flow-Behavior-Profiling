class ClientInsights:

    def safe_float(self, v):
        try:
            return float(v)
        except:
            return 0.0

    def compute(self, flow, predicted_category=None):

        protocol = int(self.safe_float(flow.get("protocol", 0)))

        syn = self.safe_float(flow.get("syn_flag_cnt", 0))
        ack = self.safe_float(flow.get("ack_flag_cnt", 0))
        rst = self.safe_float(flow.get("rst_flag_cnt", 0))
        fin = self.safe_float(flow.get("fin_flag_cnt", 0))
        psh = self.safe_float(flow.get("psh_flag_cnt", 0))

        down_up = self.safe_float(flow.get("down_up_ratio", 0))
        iat_mean = self.safe_float(flow.get("flow_iat_mean", 0))
        iat_std = self.safe_float(flow.get("flow_iat_std", 0))

        dst = int(self.safe_float(flow.get("dst_port", 0)))
        src = int(self.safe_float(flow.get("src_port", 0)))

        service = "OTHER"
        transport_protocol = "OTHER"

        if dst == 80 or src == 80:
            service = "HTTP"
        elif dst == 443 or src == 443:
            service = "HTTPS"
        elif dst == 22 or src == 22:
            service = "SSH"
        elif dst == 53 or src == 53:
            service = "DNS"
        elif dst == 21 or src == 21:
            service = "FTP"
        elif dst == 25 or src == 25:
            service = "SMTP"
        elif dst == 3306 or src == 3306:
            service = "MYSQL"
        elif dst == 3389 or src == 3389:
            service = "RDP"

        if protocol == 6:
            transport_protocol = "TCP"
        elif protocol == 17:
            transport_protocol = "UDP"
        elif protocol == 1:
            transport_protocol = "ICMP"

        beacon_score = 0.0
        if iat_mean > 0:
            beacon_score = iat_std / iat_mean
        
        trait = "Normal"

        if predicted_category == "Normal":
            if service in ["HTTP", "HTTPS"]:
                trait = "Normal web browsing activity"
            elif service == "DNS":
                trait = "Normal name resolution activity"
            elif service == "SSH":
                trait = "Normal remote administration session"
            else:
                trait = "Normal network activity"

        else:

            if syn > 0 and ack == 0:
                trait = "Handshake anomaly"

            elif rst > fin * 3 and rst > 0:
                trait = "Unstable connection pattern"

            elif beacon_score < 0.15:
                trait = "Automated periodic behavior"

            elif down_up > 10:
                trait = "Extreme download-heavy flow"

            elif down_up < 0.1:
                trait = "Extreme upload-heavy flow"

            elif 0.8 <= down_up <= 1.2:
                trait = "Balanced traffic flow"

            elif psh > 0:
                trait = "Interactive TCP session detected"


        return {
            "traits": [trait],   
            "service": service,
            "transport_protocol": transport_protocol,
            "beacon_score": round(beacon_score, 3),
            "syn": int(syn),
            "rst": int(rst),
            "ack": int(ack),
            "fin": int(fin)
        }