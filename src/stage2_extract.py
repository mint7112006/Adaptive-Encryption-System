import os
import re
import math
import joblib
import pandas as pd
from collections import Counter
from typing import Tuple, Optional, Set, List

# ==============================================================================
# 1. ĐỊNH NGHĨA PATTERNS REGEX & SHANNON ENTROPY
# ==============================================================================
PATTERNS = {
    "PII_CCCD": re.compile(r'^\d{12}$|^\d{9}$'),                                # CCCD 12 số / CMND 9 số
    "PII_PHONE": re.compile(r'^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$'),                # SĐT Việt Nam
    "PII_EMAIL": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'), # Email
    "FIN_CREDIT_CARD": re.compile(r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})$') # Credit Card
}
# Các cột hệ thống cần loại trừ khi quét dữ liệu gốc
SYSTEM_COLUMNS = [
    "stt", "source_file", "data_type", "username",
    "password_raw", "pin_raw", "salt", "password_hash", "pin_encrypted", "is_secure"
]

def calculate_entropy(text: str) -> float:
    """Tính Shannon Entropy của chuỗi ký tự."""
    if not text or text == "None":
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

# ==============================================================================
# 2. KIỂM TRA TỪNG Ô DỮ LIỆU (CELL-LEVEL INSPECTION)
# ==============================================================================
def inspect_cell_value(val_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Phân tích ô dữ liệu bằng Regex & Shannon Entropy.
    Trả về: (loại nhãn: HAS_CRED / HAS_PIN / HAS_PII_FIN, loại đặc biệt: PASSWORD / PIN)
    """
    val_str = str(val_str).strip()
    if not val_str or val_str == "None":
        return None, None

    length = len(val_str)
    entropy = calculate_entropy(val_str)

    # 1. Password: 8-32 ký tự, gồm chữ cái + (số/ký tự đặc biệt), Entropy >= 2.5
    has_alpha = any(c.isalpha() for c in val_str)
    has_digit_or_special = any(not c.isalpha() for c in val_str)
    if 8 <= length <= 32 and has_alpha and has_digit_or_special and entropy >= 2.5:
        return "HAS_CRED", "PASSWORD"

    # 2. PIN: 4-6 ký tự thuần số, Entropy từ 1.0 đến 1.5
    if val_str.isdigit() and 4 <= length <= 6 and 1.0 <= entropy <= 1.5:
        return "HAS_PIN", "PIN"

    # 3. PII / Financial Pattern: CCCD, SĐT, Email, Credit Card
    if (PATTERNS["PII_CCCD"].match(val_str) or 
        PATTERNS["PII_PHONE"].match(val_str) or 
        PATTERNS["PII_EMAIL"].match(val_str) or 
        PATTERNS["FIN_CREDIT_CARD"].match(val_str)):
        return "HAS_PII_FIN", None

    return None, None
# ==============================================================================
# 3. LUỒNG XỬ LÝ CHÍNH: QUÉT & GẮN NHÃN TỪNG DÒNG (ROW-LEVEL)
# ==============================================================================
def process_dataframe(file_path: str, model_path: str = "context_classifier.pkl") -> pd.DataFrame:
    df = pd.read_csv(file_path, encoding='utf-8-sig', dtype=str)
    original_cols = [col for col in df.columns if col not in SYSTEM_COLUMNS]

    # Đảm bảo có sẵn 2 cột chứa dữ liệu thô phục vụ mã hóa
    if 'password_raw' not in df.columns:
        df['password_raw'] = 'None'
    if 'pin_raw' not in df.columns:
        df['pin_raw'] = 'None'

    final_data_types = []

    # --- QUÉT VÀ XỬ LÝ TỪNG DÒNG ---
    for idx, row in df.iterrows():
        row_labels: Set[str] = set()

        for col in original_cols:
            val = str(row[col]).strip()
            match_type, special_type = inspect_cell_value(val)

            if match_type == "HAS_CRED":
                row_labels.add("CREDENTIALS")
                if special_type == "PASSWORD":
                    df.at[idx, 'password_raw'] = val

            elif match_type == "HAS_PIN":
                row_labels.add("FINANCIAL_PIN")
                if special_type == "PIN":
                    df.at[idx, 'pin_raw'] = val

            elif match_type == "HAS_PII_FIN":
                row_labels.add("PII")

        # Tổng hợp nhãn dòng
        if not row_labels:
            row_final_label = "NON_SENSITIVE"
        else:
            # Sắp xếp danh sách nhãn để đầu ra nhất quán (VD: "CREDENTIALS, PII")
            row_final_label = ", ".join(sorted(list(row_labels)))

        # Bảo toàn nhãn OCR nếu có từ Stage 1
        current_type = str(df.at[idx, 'data_type']) if 'data_type' in df.columns else 'None'
        if current_type.startswith("IMAGE_"):
            final_data_types.append(current_type)
        else:
            final_data_types.append(row_final_label)

    # Gán danh sách nhãn chuẩn theo dòng vào DataFrame
    df['data_type'] = final_data_types
    return df
# ==============================================================================
# 4: HÀM MAP THANG ĐIỂM NHẠY CẢM TRONG STAGE 2
# ==============================================================================
def get_sensitivity_level(data_type_str: str) -> int:
    """Chuyển đổi nhãn chuỗi sang thang điểm số (0 - 3)."""
    if "CREDENTIALS" in data_type_str:
        return 3
    elif "FINANCIAL_PIN" in data_type_str:
        return 2
    elif "PII" in data_type_str:
        return 1
    return 0

# ==============================================================================
# 5: TÍCH HỢP ĐẦU VÀO DECISION TREE Ở CUỐI STAGE 2
# ==============================================================================
def stage_2_process_with_dt(df: pd.DataFrame, dt_model) -> pd.DataFrame:
    # 1. Chạy Regex + Entropy quét dòng (đã làm ở bài trước)
    df = process_dataframe(df) # Hàm trả về cột 'data_type'
    
    chosen_algorithms = []
    
    for idx, row in df.iterrows():
        # Trích xuất 2 đặc tính chính
        sensitivity_level = get_sensitivity_level(str(row['data_type']))
        
        # Tính kích thước dòng (bytes -> KB)
        row_str = "".join([str(val) for val in row.values if pd.notna(val)])
        data_size_kb = len(row_str.encode('utf-8')) / 1024.0
        
        # Đưa 2 tham số vào Decision Tree dự đoán thuật toán
        features = [[data_size_kb, sensitivity_level]]
        predicted_algo = dt_model.predict(features)[0] # VD: 'HYBRID_AES_RSA'
        
        chosen_algorithms.append(predicted_algo)
        
    df['chosen_algorithm'] = chosen_algorithms
    return df # Trả về DataFrame sẵn sàng cho Stage 3
