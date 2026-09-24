import os
import re
import math
import pandas as pd
from typing import List, Dict, Tuple, Any
from collections import Counter

# ==============================================================================
# 1. TỪ ĐIỂN ANCHOR KEYWORDS (CẦU NỐI LỚP 1 - HEADER MAPPING)
# ==============================================================================
KEYWORDS_DB: Dict[str, List[str]] = {
    # 1. Y TẾ VIỆT NAM & QUỐC TẾ
    "MEDICAL": [
        # VN
        "benh_an", "giay_ra_vien", "giay_vao_vien", "ly_do_vao_vien", "chan_doan",
        "y_lenh", "to_dieu_tri", "don_thuoc", "toa_thuoc", "ham_luong", "cach_dung",
        "phieu_xet_nghiem", "tri_so_binh_thuong", "csbt", "x_quang", "sieu_am", "ct_scan",
        "mri", "ket_luan", "bang_ke_chi_phi", "tam_ung", "dong_chi_tra", "bhyt", "ma_bn",
        "tien_su_benh", "nhom_mau", "hien_tang",
        # International
        "medical_record", "mrn", "chief_complaint", "hpi", "pmh", "progress_notes",
        "discharge_summary", "prescription", "dispense", "refills", "lab_report",
        "reference_range", "patient_id", "diagnosis_code", "medical_history"
    ],
    
    # 2. TÀI CHÍNH VIỆT NAM & QUỐC TẾ
    "FINANCIAL": [
        # VN
        "hoa_don", "vat", "mau_so", "ky_hieu", "ma_co_quan_thue", "mst", "ma_so_thue",
        "tien_hang", "tong_cong", "sao_ke", "lich_su_giao_dich", "uy_nhiem_chi",
        "giay_bao_no", "giay_bao_co", "so_du", "so_tai_khoan", "stk", "bang_can_doi",
        "ket_qua_hoat_dong_kinh_doanh", "luu_chuyen_tien_te", "tai_san", "von_chu_so_huu",
        # International
        "invoice", "receipt", "bill_to", "ship_to", "tax_id", "vat_number", "subtotal",
        "total_due", "balance_due", "bank_statement", "posting_date", "debit", "credit",
        "balance_sheet", "income_statement", "profit_loss", "cash_flow", "revenue",
        "net_income", "iban", "swift", "bic", "routing_number"
    ],
    
    # 3. THÔNG TIN XÁC THỰC & RÒ RỈ MÃ NGUỒN (CREDENTIALS)
    "CREDENTIALS": [
        "password", "passwd", "pwd", "mat_khau", "user", "username", "admin",
        "administrator", "root", "creds", "credentials", "secret", "secret_key",
        "api_key", "apikey", "token", "access_token", "auth_token", "private_key",
        "ssh_key", "jwt", "connection_string", "db_password", "db_user"
    ],
    
    # 4. MÃ PIN & TÀI CHÍNH NHẠY CẢM
    "FINANCIAL_PIN": [
        "ma_pin", "pin", "pin_code", "ma_xac_thuc", "otp", "cvv", "cvc"
    ],
    
    # 5. DỮ LIỆU CÁ NHÂN (PII VIỆT NAM & QUỐC TẾ)
    "PII": [
        # VN
        "ho_va_ten", "ho_ten", "ten_khach_hang", "ngay_sinh", "gioi_tinh", "cmnd",
        "cccd", "can_cuoc_cong_dan", "ho_chieu", "passport", "so_dien_thoai", "sdt",
        "phone_number", "dia_chi", "email", "ket_hon", "doc_than", "so_the", "atm",
        # International
        "full_name", "first_name", "last_name", "email_address", "mobile", "street_address",
        "ssn", "social_security", "drivers_license", "national_id", "nin", "credit_card"
    ]
}

# ==============================================================================
# 2. DANH SÁCH REGEX BẮT MẪU DỮ LIỆU (LỚP 2 - PATTERN MATCHING)
# ==============================================================================
PATTERNS_DB = {
    "PII_CCCD": re.compile(r'^\d{12}$|^\d{9}$'),                                        # CCCD 12 số / CMND 9 số VN
    "PII_PHONE": re.compile(r'^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$'),                        # Số điện thoại VN
    "PII_EMAIL": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),       # Email
    "PII_SSN": re.compile(r'^\d{3}-\d{2}-\d{4}$'),                                     # SSN Mỹ
    "FIN_CREDIT_CARD": re.compile(r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})$'), # VISA/MasterCard/Amex
    "FIN_MST": re.compile(r'^\d{10}(?:-\d{3})?$'),                                      # Mã số thuế Việt Nam
    "MED_ICD10": re.compile(r'^[A-Z][0-9]{2}(?:\.[0-9]{1,2})?$'),                       # Mã bệnh ICD-10
    "CREDENTIAL_CONNSTR": re.compile(r'^(mongodb|postgres|mysql|redis):\/\/[^\s]+$'),  # Database Connection String
    "CREDENTIAL_JWT": re.compile(r'^ey[Jj][a-zA-Z0-9_-]+\.ey[Jj][a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$') # JWT Token
}


# ==============================================================================
# 3. THUẬT TOÁN TÍNH SHANNON ENTROPY (LỚP 3 - STATISTICAL ANALYSIS)
# ==============================================================================
def calculate_entropy(text: str) -> float:
    """Tính độ hỗn loạn thông tin Shannon Entropy (đơn vị: bits/character)."""
    if not text or text == 'None':
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# ==============================================================================
# 4. HÀM KIỂM TRA GIÁ TRỊ Ô (INSPECT VALUE TYPE - LỚP 2 & 3)
# ==============================================================================
def inspect_value_type(val_str: str) -> str:
    """Đánh giá giá trị chuỗi dựa trên Regex và Shannon Entropy."""
    val_str = str(val_str).strip()
    if not val_str or val_str == 'None':
        return "NON_SENSITIVE"

    length = len(val_str)

    # --- QUA LỚP 2: KIỂM TRA PATTERN REGEX ---
    if PATTERNS_DB["CREDENTIAL_CONNSTR"].match(val_str) or PATTERNS_DB["CREDENTIAL_JWT"].match(val_str):
        return "CREDENTIALS"
    if PATTERNS_DB["PII_CCCD"].match(val_str) or PATTERNS_DB["PII_PHONE"].match(val_str) or PATTERNS_DB["PII_EMAIL"].match(val_str) or PATTERNS_DB["PII_SSN"].match(val_str):
        return "PII"
    if PATTERNS_DB["FIN_CREDIT_CARD"].match(val_str) or PATTERNS_DB["FIN_MST"].match(val_str):
        return "FINANCIAL"
    if PATTERNS_DB["MED_ICD10"].match(val_str):
        return "MEDICAL"

    # --- QUA LỚP 3: DỰA TRÊN SHANNON ENTROPY & CẤU TRÚC KÝ TỰ ---
    entropy = calculate_entropy(val_str)

    # 1. Kiểm tra Mã PIN (Chuỗi thuần số, dài 4-6 ký tự)
    if val_str.isdigit() and 4 <= length <= 6:
        if entropy >= 1.0: # PIN không lặp đơn điệu như '0000'
            return "FINANCIAL_PIN"

    # 2. Kiểm tra Mật khẩu / Secret Key
    if 8 <= length <= 64:
        has_alpha = any(c.isalpha() for c in val_str)
        has_digit = any(c.isdigit() for c in val_str)
        has_special = any(not c.isalnum() for c in val_str)
        
        # Mật khẩu mạnh thường có độ hỗn loạn cao (Entropy >= 2.8) và pha trộn nhiều tập ký tự
        if entropy >= 2.8 and (has_alpha and (has_digit or has_special)):
            return "CREDENTIALS"

    return "NON_SENSITIVE"


# ==============================================================================
# 5. CORE PIPELINE: STAGE 2 CLASSIFICATION
# ==============================================================================
def run_stage_2(stage1_files: List[str], output_dir: str = "processed_data") -> List[str]:
    """
    Thực thi Stage 2: Nhận danh sách các file CSV từ Stage 1, quét phân loại qua 3 Lớp lọc,
    cập nhật các cột SYSTEM_COLUMNS và xuất kết quả.
    """
    os.makedirs(output_dir, exist_ok=True)
    stage2_created_files = []

    print("==================================================")
    print("Bắt đầu Stage 2: Classification (Phân loại dữ liệu)")
    print("==================================================")

    for file_path in stage1_files:
        if not os.path.exists(file_path):
            print(f"[!] File không tồn tại: {file_path}")
            continue

        print(f"-> Đang xử lý file Stage 1: {file_path}")
        df = pd.read_csv(file_path, encoding='utf-8-sig', dtype=str)

        # Duyệt từng dòng dữ liệu trong DataFrame
        for idx, row in df.iterrows():
            row_data_type = "NON_SENSITIVE"

            # Duyệt từng cột trong dòng
            for col in df.columns:
                # Bỏ qua các cột hệ thống khi quét logic phân loại
                if col in ["stt", "source_file", "data_type", "salt", "password_hash", "pin_encrypted", "is_secure"]:
                    continue

                val = str(row[col]).strip()
                if val == 'None' or not val:
                    continue

                # -------------------------------------------------------------
                # LỚP 1: HEADER KEYWORD MAPPING (CẤP CỘT)
                # -------------------------------------------------------------
                cell_type = "NON_SENSITIVE"
                for target_type, keywords in KEYWORDS_DB.items():
                    if any(kw in col for kw in keywords):
                        cell_type = target_type
                        break

                # -------------------------------------------------------------
                # LỚP 2 & 3: INSPECTION VALUE PATTERN & ENTROPY (CẤP Ô)
                # (Nếu Lớp 1 chưa tìm thấy nhãn nhạy cảm)
                # -------------------------------------------------------------
                if cell_type == "NON_SENSITIVE":
                    cell_type = inspect_value_type(val)
                # ------------------------------------------------------------------
                # GÁN DỮ LIỆU VÀO CÁC CỘT HỆ THỐNG DỰA TRÊN NHÃN NHẬN DIỆN ĐƯỢC
                # ------------------------------------------------------------------
                if cell_type == "CREDENTIALS":
                    df.at[idx, 'password_raw'] = val
                    row_data_type = "CREDENTIALS"

                elif cell_type == "FINANCIAL_PIN":
                    df.at[idx, 'pin_raw'] = val
                    # Chỉ gán nhãn dòng là FINANCIAL_PIN nếu dòng đó chưa có nhãn nào khác
                    if row_data_type == "NON_SENSITIVE":
                        row_data_type = "FINANCIAL_PIN"

                elif cell_type in ["MEDICAL", "PII", "FINANCIAL"]:
                    # Nếu gặp MEDICAL/PII/FINANCIAL thì ưu tiên ghi đè lên NON_SENSITIVE hoặc FINANCIAL_PIN
                    if row_data_type in ["NON_SENSITIVE", "FINANCIAL_PIN"]:
                        row_data_type = cell_type


            # Cập nhật nhãn loại dữ liệu cuối cùng cho cả dòng
            # Ngoại lệ: Giữ lại nhãn IMAGE_OCR / IMAGE_ERROR nếu dòng đó đến từ OCR ảnh
            current_data_type = str(df.at[idx, 'data_type'])
            if not current_data_type.startswith("IMAGE_"):
                df.at[idx, 'data_type'] = row_data_type

        # Xuất file kết quả Stage 2
        base_name = os.path.basename(file_path)
        out_name = base_name.replace("stage1_", "stage2_")
        out_path = os.path.join(output_dir, out_name)

        df.to_csv(out_path, index=False, encoding='utf-8-sig', na_rep='None')
        print(f"   [✓] Đã xuất file Stage 2: {out_path}")
        stage2_created_files.append(out_path)

    return stage2_created_files


