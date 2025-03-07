import os
import json
import csv
import subprocess

# Cấu hình cloud provider (Azure)
CLOUD_PROVIDER = "azure"
OUTPUT_DIR = "scoutsuite-report"
REPORT_FILE = f"{OUTPUT_DIR}/scoutsuite-results.json"
CSV_FILE = f"{OUTPUT_DIR}/azure_security_report.csv"

def run_scoutsuite():
    """Chạy ScoutSuite để quét bảo mật Azure."""
    print("[+] Đang chạy ScoutSuite cho Azure...")
    try:
        command = f"python scout.py {CLOUD_PROVIDER} --report-dir {OUTPUT_DIR}"
        subprocess.run(command, shell=True, check=True)
        print("[+] Quét hoàn tất! Báo cáo đã được lưu.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi chạy ScoutSuite: {e}")
        exit(1)

def analyze_report():
    """Phân tích báo cáo và xuất kết quả ra CSV."""
    if not os.path.exists(REPORT_FILE):
        print(f"[!] Không tìm thấy báo cáo: {REPORT_FILE}")
        exit(1)

    print("[+] Đang phân tích báo cáo Azure...")
    with open(REPORT_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Lọc các cảnh báo mức độ cao
    critical_issues = []
    for service, findings in data["services"].items():
        for finding in findings["findings"]:
            if finding["level"] in ["high", "critical"]:
                critical_issues.append([
                    service,
                    finding["title"],
                    finding["level"],
                    finding.get("description", "Không có mô tả"),
                    finding.get("resource", "Không xác định")
                ])

    if critical_issues:
        print("\n[+] Các lỗ hổng nghiêm trọng phát hiện trong Azure:")
        for issue in critical_issues:
            print(f"- [{issue[2].upper()}] {issue[1]} ({issue[0]})")
            print(f"  Mô tả: {issue[3]}")
            print(f"  Tài nguyên ảnh hưởng: {issue[4]}\n")
    else:
        print("[+] Không phát hiện lỗ hổng nghiêm trọng nào trong Azure!")

    # Xuất báo cáo ra CSV
    write_to_csv(critical_issues)

def write_to_csv(data):
    """Ghi dữ liệu lỗ hổng ra file CSV."""
    headers = ["Dịch vụ", "Tên Lỗ Hổng", "Mức Độ", "Mô Tả", "Tài Nguyên Ảnh Hưởng"]
    
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(data)

    print(f"[+] Báo cáo CSV đã được lưu tại: {CSV_FILE}")

if __name__ == "__main__":
    run_scoutsuite()
    analyze_report()
