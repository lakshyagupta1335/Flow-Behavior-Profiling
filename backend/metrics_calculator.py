class MetricsCalculator:

    PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MYSQL",
        3389: "RDP"
    }

    def safe_float(self, v):
        if v is None:
            return 0.0
        try:
            return float(v)
        except:
            return 0.0

    def get_protocol_category(self, flow):
        proto = int(self.safe_float(flow.get("protocol", 0)))
        dst = int(self.safe_float(flow.get("dst_port", 0)))
        src = int(self.safe_float(flow.get("src_port", 0)))

        return (
            self.SERVICE_MAP.get(dst)
            or self.SERVICE_MAP.get(src)
            or self.PROTOCOL_MAP.get(proto, "OTHER")
        )

    def compute(self, flow):

        required = [
            "flow_duration",
            "flow_byts_s",
            "flow_pkts_s",
            "totlen_fwd_pkts",
            "totlen_bwd_pkts",
            "tot_fwd_pkts",
            "tot_bwd_pkts"
        ]

        if not all(k in flow for k in required):
            return None

        try:
            # bytes
            fwd_bytes = self.safe_float(flow["totlen_fwd_pkts"])
            bwd_bytes = self.safe_float(flow["totlen_bwd_pkts"])
            total_bytes = fwd_bytes + bwd_bytes

            # packets
            fwd_pkts = self.safe_float(flow["tot_fwd_pkts"])
            bwd_pkts = self.safe_float(flow["tot_bwd_pkts"])
            total_pkts = fwd_pkts + bwd_pkts

            # duration
            duration_sec = max(self.safe_float(flow["flow_duration"]), 0.001)

            # data rate (bytes/sec → Mbps)
            flow_bytes_s = self.safe_float(flow["flow_byts_s"])
            throughput_mbps = (flow_bytes_s * 8) / 1_000_000

            # upload/download split
            if total_bytes > 0:
                upload_mbps = throughput_mbps * (fwd_bytes / total_bytes)
                download_mbps = throughput_mbps * (bwd_bytes / total_bytes)
            else:
                upload_mbps = 0.0
                download_mbps = 0.0

            # packet rate
            packet_rate_pps = self.safe_float(flow["flow_pkts_s"])

            # avg packet size
            avg_packet_size = total_bytes / total_pkts if total_pkts else 0.0

            # direction
            direction = "Balanced"
            if fwd_pkts > bwd_pkts * 1.2:
                direction = "Outbound Heavy"
            elif bwd_pkts > fwd_pkts * 1.2:
                direction = "Inbound Heavy"

            return {
                "throughput_mbps": round(throughput_mbps, 3),
                "upload_mbps": round(upload_mbps, 3),
                "download_mbps": round(download_mbps, 3),

                "flow_duration_ms": round(duration_sec * 1000, 2),

                "packet_rate_pps": round(packet_rate_pps, 3),
                "avg_packet_size": round(avg_packet_size, 2),

                "direction": direction,
                "protocol_category": self.get_protocol_category(flow),

                "raw_total_bytes": total_bytes,
                "raw_fwd_bytes": fwd_bytes,
                "raw_bwd_bytes": bwd_bytes,
            }

        except Exception as e:
            print("[METRICS ERROR]", e)
            return None

