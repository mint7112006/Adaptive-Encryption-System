import os
import base64
import re
import pandas as pd
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Sử dụng regex biên từ, hỗ trợ tốt cả tên cột tiếng Việt không dấu/có dấu chuẩn
SENSITIVE_COLUMNS_EXACT = {
    "cccd", "sdt", "phone", "email", "the_tin_dung", "credit_card", 
    "password", "mat_khau", "pin", "ma_pin", "dia_chi", "address", "ten", "name"
}

def is_sensitive_column(col_name: str) -> bool:
    col_lower = str(col_name).lower().strip()
    for kw in SENSITIVE_COLUMNS_EXACT:
        if re.search(r'\b' + re.escape(kw) + r'\b', col_lower):
            return True
    return False

def stage_3_bulletproof_enforcement(df: pd.DataFrame, rsa_public_key_bytes: bytes, original_filename: str = "dataset.csv", output_dir: str = "encrypt") -> str:
    """
    Xử lý Stage 3 chuẩn mực bảo mật cao nhất: An toàn tuyệt đối với tên cột tiếng Việt, 
    không lệch metadata, chống crash thư mục và kiểm soát trạng thái toàn vẹn dữ liệu.
    """
    # 1. Khắc phục lỗi makedirs: Tạo thư mục ngay từ đầu hàm trước mọi thao tác file/log
    os.makedirs(output_dir, exist_ok=True)

    rsa_pub_key = RSA.import_key(rsa_public_key_bytes)
    rsa_cipher_cache = PKCS1_OAEP.new(rsa_pub_key)
    RSA_MAX_BYTES = 190  # Giới hạn an toàn tuyệt đối cho PKCS1_OAEP

    target_columns = [col for col in df.columns if is_sensitive_column(col) and not col.endswith('_raw')]
    print(f"[i] Các cột PII/Credentials được xác thực chính xác: {target_columns}")

    is_secure_statuses = []
    error_logs = []

    # 2. Quay lại dùng iterrows() để loại bỏ hoàn toàn rủi ro mangle tên cột tiếng Việt/ký tự đặc biệt
    for idx, row in df.iterrows():
        algo = str(row.get('chosen_algorithm', 'NONE')).strip()
        
        if algo == "NONE" or not target_columns:
            is_secure_statuses.append("False")
            continue

        row_fully_secured = True
        cols_attempted = 0
        cols_secured = 0

        for col in target_columns:
            raw_val = row.get(col, None)
            if pd.isna(raw_val) or str(raw_val).strip() in ["None", "nan", ""]:
                continue

            cols_attempted += 1
            val_str = str(raw_val)
            
            try:
                current_algo = algo
                
                # 3. Xử lý thông minh: Nếu tràn giới hạn RSA, tự nâng cấp thuật toán cho RIÊNG Ô ĐÓ 
                # mà không làm hỏng metadata chung của cả dòng.
                if current_algo == "RSA-2048" and len(val_str.encode('utf-8')) > RSA_MAX_BYTES:
                    current_algo = "HYBRID_AES_RSA"

                if current_algo == "RSA-2048":
                    enc_bytes = rsa_cipher_cache.encrypt(val_str.encode('utf-8'))
                    encrypted_val = base64.b64encode(enc_bytes).decode('utf-8')
                    cols_secured += 1

                elif current_algo in ["ChaCha20-Poly1305", "HYBRID_AES_RSA"]:
                    # Mã hóa phong bì (Envelope Encryption)
                    sym_key = get_random_bytes(32)
                    if current_algo == "ChaCha20-Poly1305":
                        cipher_sym = ChaCha20_Poly1305.new(key=sym_key)
                    else:
                        cipher_sym = AES.new(sym_key, AES.MODE_GCM)

                    ciphertext, tag = cipher_sym.encrypt_and_digest(val_str.encode('utf-8'))
                    nonce = cipher_sym.nonce
                    enc_sym_key = rsa_cipher_cache.encrypt(sym_key)

                    payload = {
                        "enc_key": base64.b64encode(enc_sym_key).decode('utf-8'),
                        "nonce": base64.b64encode(nonce).decode('utf-8'),
                        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                        "tag": base64.b64encode(tag).decode('utf-8')
                    }
                    # Payload tự mô tả (Self-describing) phân tách bằng dấu |
                    encrypted_val = f"{payload['enc_key']}|{payload['nonce']}|{payload['ciphertext']}|{payload['tag']}"
                    cols_secured += 1
                else:
                    encrypted_val = val_str

                df.at[idx, col] = encrypted_val

            except Exception as e:
                row_fully_secured = False
                err_msg = f"[LỖI MÃ HÓA] Dòng {idx}, Cột '{col}': {str(e)}"
                error_logs.append(err_msg)

        if cols_attempted > 0 and cols_secured == cols_attempted and row_fully_secured:
            is_secure_statuses.append("True")
        else:
            is_secure_statuses.append("False")

    df['is_secure'] = is_secure_statuses

    # Dọn dẹp dữ liệu thô an toàn
    if 'password_raw' in df.columns:
        df['password_raw'] = "REDACTED"
    if 'pin_raw' in df.columns:
        df['pin_raw'] = "REDACTED"

    # Ghi log lỗi chuyên nghiệp (thư mục chắc chắn đã tồn tại)
    if error_logs:
        log_path = os.path.join(output_dir, "encryption_audit_error.log")
        with open(log_path, "w", encoding="utf-8") as log_file:
            log_file.write("\n".join(error_logs))
        print(f"[!] Cảnh báo bảo mật: Có {len(error_logs)} lỗi phát sinh. Chi tiết ghi tại: {log_path}")

    base_name = os.path.basename(original_filename)
    output_path = os.path.join(output_dir, f"stage3_secured_{base_name}")
    df.to_csv(output_path, index=False, encoding='utf-8-sig')
    
    print(f"[✓] Stage 3 hoàn tất tuyệt đối! Tệp an toàn lưu tại: {output_path}")
    return output_path

def stage_3_batch_enforcement(file_paths: list, rsa_public_key_bytes: bytes, output_dir: str = "stage3_encrypt") -> list:
    """
    Hàm bọc (Wrapper): Nhận vào danh sách đường dẫn file từ Stage 2,
    lần lượt đọc từng file thành DataFrame rồi gọi hàm stage_3_bulletproof_enforcement để xử lý.
    Trả về danh sách các tệp đã được mã hóa an toàn.
    """
    secured_file_paths = []
    
    if not file_paths:
        print("[!] Danh sách file đầu vào Stage 3 trống.")
        return secured_file_paths

    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"[!] Không tìm thấy file: {file_path}")
            continue
            
        print(f"\n[i] Đang đọc file cho Stage 3: {file_path}")
        # Đọc file CSV thành DataFrame
        df = pd.read_csv(file_path, dtype=str)
        
        # Gọi lại hàm gốc xử lý từng DataFrame
        secured_path = stage_3_bulletproof_enforcement(
            df=df, 
            rsa_public_key_bytes=rsa_public_key_bytes, 
            original_filename=file_path, 
            output_dir=output_dir
        )
        
        if secured_path:
            secured_file_paths.append(secured_path)
            
    print(f"\n[✓] Stage 3 hoàn tất toàn bộ! Đã tạo {len(secured_file_paths)} file an toàn.")
    return secured_file_paths