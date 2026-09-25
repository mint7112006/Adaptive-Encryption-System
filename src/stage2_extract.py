import os
import re
import math
import joblib
import pandas as pd
from collections import Counter
from typing import Tuple, Optional, Set, List

# ==============================================================================
# 1. ĐỊNH NGHĨA BẢNG ÁNH XẠ, PATTERNS REGEX & UTILS
# ==============================================================================
ALGO_MAP = {
    0: "NONE",
    1: "RSA-2048",
    2: "ChaCha20-Poly1305",
    3: "HYBRID_AES_RSA"
}

PATTERNS = {
    "PII_CCCD": re.compile(r'^(?:\d{9}|\d{12})$'),
    "PII_PHONE": re.compile(r'^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$'),
    "PII_EMAIL": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    "FIN_CREDIT_CARD": re.compile(r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})$')
}

STRUCTURED_PATTERNS = [
    re.compile(r'^\d{4}-\d{2}-\d{2}(?:T|\s)\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$'), # Datetime
    re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'), # UUID
    re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') # IPv4
]

SYSTEM_COLUMNS = [
    "stt", "source_file", "data_type", "username",
    "password_raw", "pin_raw", "salt", "password_hash", "pin_encrypted", "is_secure", "chosen_algorithm"
]

NULL_VALUES = {"none", "null", "n/a", "undefined", "", "nan"}

def calculate_password_strength_bits(text: str) -> float:
    if not text or text.lower() in NULL_VALUES:
        return 0.0
    
    pool_size = 0
    if re.search(r'[a-z]', text):
        pool_size += 26
    if re.search(r'[A-Z]', text):
        pool_size += 26
    if re.search(r'[0-9]', text):
        pool_size += 10
    if re.search(r'\s', text):
        pool_size += 1
    if re.search(r'[^a-zA-Z0-9\s]', text):
        pool_size += 32
        
    if pool_size == 0:
        return 0.0
        
    return len(text) * math.log2(pool_size)

def looks_like_year_or_date(val_str: str) -> bool:
    length = len(val_str)
    if length == 4:
        try:
            year_val = int(val_str)
            if 1900 <= year_val <= 2100:
                return True
        except ValueError:
            pass
    elif length == 6:
        try:
            dd, mm = int(val_str[:2]), int(val_str[2:4])
            if 1 <= dd <= 31 and 1 <= mm <= 12:
                return True
        except ValueError:
            pass
    return False

# ==============================================================================
# 2. PHÂN TÍCH ĐỘNG CÁC CỘT MÃ ĐỊNH DANH (COLUMN-LEVEL CONTEXT)
# ==============================================================================
def analyze_column_types(df: pd.DataFrame) -> Set[str]:
    ignored_cols = set()
    
    for col in df.columns:
        if col in SYSTEM_COLUMNS:
            continue
        
        col_lower = str(col).lower()
        tokens = set(re.split(r'[_+\-\s]+', col_lower))
        
        if any(kw in tokens or kw in col_lower for kw in ["pass", "password", "pin", "mat_khau"]):
            continue

        if any(t in tokens for t in ["id", "code", "stt", "uuid", "guid"]):
            ignored_cols.add(col)
            continue

        valid_series = df[col].dropna().astype(str).str.strip()
        if len(valid_series) == 0:
            continue

        has_hyphen_prefix = valid_series.apply(lambda x: bool(re.match(r'^[A-Za-z0-9]{2,6}-', x)))
        if has_hyphen_prefix.mean() > 0.7:
            ignored_cols.add(col)
            
    return ignored_cols

# ==============================================================================
# 3. KIỂM TRA TỪNG Ô DỮ LIỆU (CELL-LEVEL INSPECTION)
# ==============================================================================
def inspect_cell_value(val_str: str, is_ignored_col: bool, col_name: str = "") -> Tuple[Optional[str], Optional[str]]:
    val_str = str(val_str).strip()
    if not val_str or val_str.lower() in NULL_VALUES:
        return None, None

    for pattern in STRUCTURED_PATTERNS:
        if pattern.match(val_str):
            return None, None

    is_pii = (PATTERNS["PII_CCCD"].match(val_str) or 
              PATTERNS["PII_PHONE"].match(val_str) or 
              PATTERNS["PII_EMAIL"].match(val_str) or 
              PATTERNS["FIN_CREDIT_CARD"].match(val_str))
    
    if is_pii:
        return "HAS_PII_FIN", None

    if is_ignored_col:
        return None, None

    length = len(val_str)
    col_lower = str(col_name).lower()
    is_pin_col = any(kw in col_lower for kw in ["pin", "pincode", "ma_pin"])

    if val_str.isdigit() and 4 <= length <= 6:
        if is_pin_col:
            return "HAS_PIN", "PIN"
        if not looks_like_year_or_date(val_str) and len(set(val_str)) > 1:
            return "HAS_PIN", "PIN"

    if 8 <= length <= 64:
        has_alpha = any(c.isalpha() for c in val_str)
        has_digit = any(c.isdigit() for c in val_str)
        has_special = bool(re.search(r'[^a-zA-Z0-9\s]', val_str))
        
        cond_alpha_digit = has_alpha and has_digit
        cond_alpha_special = has_alpha and has_special
        cond_passphrase = length >= 14 and has_alpha

        if cond_alpha_digit or cond_alpha_special or cond_passphrase:
            strength_bits = calculate_password_strength_bits(val_str)
            if strength_bits >= 30.0:
                return "HAS_CRED", "PASSWORD"

    return None, None

# ==============================================================================
# 4. LUỒNG XỬ LÝ CHÍNH
# ==============================================================================
def process_dataframe(file_path: str) -> pd.DataFrame:
    df = pd.read_csv(file_path, encoding='utf-8-sig', dtype=str)
    
    ignored_code_cols = analyze_column_types(df)
    scan_cols = [col for col in df.columns if col not in SYSTEM_COLUMNS]

    if 'password_raw' not in df.columns:
        df['password_raw'] = 'None'
    if 'pin_raw' not in df.columns:
        df['pin_raw'] = 'None'

    final_data_types = []

    for idx, row in df.iterrows():
        row_labels: Set[str] = set()

        for col in scan_cols:
            val = str(row[col]).strip()
            is_ignored = col in ignored_code_cols
            
            match_type, special_type = inspect_cell_value(val, is_ignored, col_name=col)

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

        if not row_labels:
            row_final_label = "NON_SENSITIVE"
        else:
            row_final_label = ", ".join(sorted(list(row_labels)))

        current_type = str(df.at[idx, 'data_type']) if 'data_type' in df.columns else 'None'
        if current_type.startswith("IMAGE_"):
            final_data_types.append(current_type)
        else:
            final_data_types.append(row_final_label)

    df['data_type'] = final_data_types
    return df

# ==============================================================================
# 5. CHUYỂN ĐỔI THANG ĐIỂM NHẠY CẢM (0 - 3)
# ==============================================================================
def get_sensitivity_level(data_type_str: str) -> int:
    data_type_str = str(data_type_str).upper()
    if "CREDENTIALS" in data_type_str:
        return 3
    elif "FINANCIAL_PIN" in data_type_str or "PIN" in data_type_str:
        return 2
    elif "PII" in data_type_str:
        return 1
    return 0

# ==============================================================================
# 6. TÍCH HỢP DECISION TREE DỰ ĐOÁN THUẬT TOÁN (TÍNH PAYLOAD SẠCH)
# ==============================================================================
def stage_2_process_with_dt(created_files: List[str], dt_model, output_dir: str = "processed_data") -> List[str]:
    processed_file_paths = []

    if isinstance(created_files, str):
        created_files = [created_files]

    for file_path in created_files:
        df = process_dataframe(file_path)
        
        # 1. Lấy kích thước thực tế của toàn bộ file trên ổ đĩa (tính bằng KB)
        file_size_bytes = os.path.getsize(file_path)
        file_size_kb = round(file_size_bytes / 1024.0, 4)  # Đã sửa lỗi thiếu dấu ngoặc đóng ở đây
        
        original_data_cols = [col for col in df.columns if col not in SYSTEM_COLUMNS and col not in ['data_size_kb', 'sensitivity_level']]
        
        data_sizes = []
        sensitivity_levels = []
        
        for idx, row in df.iterrows():
            s_level = get_sensitivity_level(str(row['data_type']))
            
            # Nếu file lớn và chứa PII/Credentials (tổng file nặng > 5KB), 
            # ta có thể ép hoặc giữ nguyên s_level để mô hình đẩy lên mức bảo mật cao.
            # (Tuỳ chọn: Nếu muốn ép toàn bộ file PII 1000 dòng thành Hybrid, có thể quy đổi s_level = 3 nếu file_size_kb > 10.0)
            if file_size_kb > 10.0 and s_level >= 1:
                s_level = 3  # Đẩy lên mức tối đa để kích hoạt HYBRID_AES_RSA trong cây quyết định

            data_sizes.append(file_size_kb)
            sensitivity_levels.append(s_level)

        df['data_size_kb'] = data_sizes
        df['sensitivity_level'] = sensitivity_levels

        # Batch Prediction tối ưu hiệu năng
        features_df = df[['data_size_kb', 'sensitivity_level']]
        pred_codes = dt_model.predict(features_df)

        df['chosen_algorithm'] = [ALGO_MAP.get(code, "NONE") for code in pred_codes]

        # Đồng nhất các ô rỗng/NaN thành chuỗi "None"
        df = df.fillna("None").replace(r'^\s*$', "None", regex=True)

        os.makedirs(output_dir, exist_ok=True)
        base_name = os.path.basename(file_path)
        output_file_name = f"stage2_processed_{base_name}"
        save_path = os.path.join(output_dir, output_file_name)

        df.to_csv(save_path, index=False, encoding='utf-8-sig')
        print(f"[✓] Stage 2 hoàn tất! Đã lưu kết quả tại: {save_path}")

        processed_file_paths.append(save_path)

    return processed_file_paths