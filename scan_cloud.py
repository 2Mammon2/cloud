import os
import json
import csv
import subprocess

# Cấu hình đường dẫn và môi trường
SCOUTSUITE_PATH = "/home/kali/toolcloud/ScoutSuite/scout.py"  # Đường dẫn chính xác đến scout.py
VENV_PATH = "/home/kali/toolcloud/ScoutSuite/scoutenv/bin/activate"  # Đường dẫn môi trường ảo
OUTPUT_DIR = "scoutsuite-report"
CSV_FILE = f"{OUTPUT_DIR}/azure_security_report.csv"

def get_subscription_id():
    """Yêu cầu người dùng nhập Subscription ID của Azure."""
    sub_id = input("🔹 Nhập Azure Subscription ID: ").strip()
    if not sub_id:
        print("[!] Subscription ID không hợp lệ! Hãy nhập lại.")
        exit(1)
    return sub_id

def run_scoutsuite(subscription_id):
    """Chạy ScoutSuite nhưng không xuất file, lấy dữ liệu từ terminal."""
    print(f"[+] Đang chạy ScoutSuite cho Azure (Subscription: {subscription_id})...")
    try:
        command = f"source {VENV_PATH} && python3 {SCOUTSUITE_PATH} azure --subscriptions {subscription_id} -c --no-browser --no-report-generator --quiet"
        
        # Chạy lệnh và lấy dữ liệu JSON từ stdout
        result = subprocess.run(command, shell=True, check=True, executable="/bin/bash", capture_output=True, text=True)
        scout_data = json.loads(result.stdout)  # Chuyển output thành JSON
        
        print("[+] Quét hoàn tất! Đang phân tích dữ liệu...")
        return scout_data
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi chạy ScoutSuite: {e}")
        exit(1)

def analyze_report(data):
    """Phân tích dữ liệu quét từ ScoutSuite."""
    print("[+] Đang phân tích báo cáo Azure...")

    # Lọc các cảnh báo mức độ cao
    critical_issues = []
    for service, findings in data.get("services", {}).items():
        for finding in findings.get("findings", []):
            if finding.get("level") in ["high", "critical"]:
                critical_issues.append([
                    service,
                    finding.get("title", "Không có tiêu đề"),
                    finding.get("level", "Không xác định"),
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
    
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)  # Tạo thư mục nếu chưa có

    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(data)

    print(f"[+] Báo cáo CSV đã được lưu tại: {CSV_FILE}")

if __name__ == "__main__":
    subscription_id = get_subscription_id()  # Yêu cầu nhập Subscription ID
    scout_data = run_scoutsuite(subscription_id)  # Nhận dữ liệu JSON từ terminal
    analyze_report(scout_data)  # Phân tích và xuất CSV
