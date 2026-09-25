import os
import time
import base64
import re
import pandas as pd
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.PublicKey import RSA

# Sử dụng chung bộ lọc cột nhạy cảm để Stage 4 quét chính xác 100% như Stage 3
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

def decrypt_value(encrypted_str: str, rsa_cipher_dec) -> tuple[str, str]:
    """
    Giải mã tự động dựa trên self-describing payload, nhận vào cipher object đã khởi tạo sẵn
    để tối ưu tuyệt đối thời gian benchmark.
    """
    if not encrypted_str or str(encrypted_str).strip() in ["None", "nan", ""]:
        return "None", "NONE"
    
    encrypted_str = str(encrypted_str)
    parts = encrypted_str.split('|')
    
    try:
        # Định dạng RSA-2048 thuần (1 phần)
        if len(parts) == 1:
            decoded_bytes = base64.b64decode(encrypted_str.encode('utf-8'))
            plain_bytes = rsa_cipher_dec.decrypt(decoded_bytes)
            return plain_bytes.decode('utf-8'), "RSA-2048"
            
        # Định dạng Mã hóa phong bì (Hybrid / ChaCha20 - tổng 4 phần)
        elif len(parts) == 4:
            enc_sym_key_b64, nonce_b64, ciphertext_b64, tag_b64 = parts
            
            enc_sym_key = base64.b64decode(enc_sym_key_b64.encode('utf-8'))
            nonce = base64.b64decode(nonce_b64.encode('utf-8'))
            ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
            tag = base64.b64decode(tag_b64.encode('utf-8'))
            
            sym_key = rsa_cipher_dec.decrypt(enc_sym_key)
            
            try:
                cipher_aes = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
                plain_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
                return plain_bytes.decode('utf-8'), "HYBRID_AES_RSA"
            except Exception:
                cipher_chacha = ChaCha20_Poly1305.new(key=sym_key, nonce=nonce)
                plain_bytes = cipher_chacha.decrypt_and_verify(ciphertext, tag)
                return plain_bytes.decode('utf-8'), "ChaCha20-Poly1305"
        else:
            # Xử lý dứt điểm payload hỏng (có 2 hoặc 3 phần) tránh lọt vào UNKNOWN
            return encrypted_str, "INVALID_FORMAT"
                
    except Exception as e:
        print(f"[!] Lỗi giải mã giá trị: {e}")
        return "[DECRYPTION_FAILED]", "ERROR"
        
    return encrypted_str, "UNKNOWN"

def stage_4_benchmark_and_show(stage3_file_path: str, rsa_private_key_bytes: bytes, output_dir: str = "reports") -> tuple[str, pd.DataFrame]:
    """
    Stage 4 hoàn thiện chuẩn học thuật: Parse RSA key 1 lần duy nhất, loại bỏ tuyệt đối các payload dị biệt.
    """
    df = pd.read_csv(stage3_file_path, encoding='utf-8-sig', dtype=str)
    
    # Khởi tạo khóa RSA MỘT LẦN DUY NHẤT ở đây để không làm sai lệch thời gian benchmark từng ô
    rsa_priv_key = RSA.import_key(rsa_private_key_bytes)
    rsa_cipher_dec = PKCS1_OAEP.new(rsa_priv_key)
    
    encrypted_cols = [col for col in df.columns if is_sensitive_column(col) and not col.endswith('_raw')]
    print(f"[i] Các cột PII được Stage 4 nhận diện để giải mã và đo đạc: {encrypted_cols}")
    
    benchmark_records = []
    decrypted_df = df.copy()
    
    for idx, row in df.iterrows():
        algo = str(row.get('chosen_algorithm', 'NONE')).strip()
        
        if algo == "NONE":
            continue
            
        for col in encrypted_cols:
            cell_val = row.get(col, None)
            if pd.isna(cell_val) or str(cell_val).strip() in ["None", "nan", ""]:
                continue
                
            input_size = len(str(cell_val).encode('utf-8'))
            
            # Đo thời gian giải mã chuẩn xác (không bị cộng dồn thời gian parse RSA key)
            start_time = time.perf_counter()
            plain_val, actual_algo = decrypt_value(cell_val, rsa_cipher_dec)
            end_time = time.perf_counter()
            
            decryption_time_ms = (end_time - start_time) * 1000.0
            output_size = len(str(plain_val).encode('utf-8'))
            overhead_ratio = (input_size / output_size) if output_size > 0 else 0.0
            
            decrypted_df.at[idx, f"{col}_decrypted"] = plain_val
            
            # Chỉ ghi nhận metric khi thuật toán thực sự thành công, loại bỏ toàn bộ lỗi và định dạng hỏng
            if actual_algo not in ("ERROR", "UNKNOWN", "INVALID_FORMAT", "NONE"):
                benchmark_records.append({
                    "algorithm": actual_algo,
                    "column": col,
                    "decrypt_time_ms": decryption_time_ms,
                    "input_size_bytes": input_size,
                    "output_size_bytes": output_size,
                    "overhead_ratio": overhead_ratio
                })
            
    # Tổng hợp báo cáo chuẩn xác
    bench_df = pd.DataFrame(benchmark_records)
    if not bench_df.empty:
        summary_report = bench_df.groupby("algorithm").agg(
            total_samples=("decrypt_time_ms", "count"),
            avg_decrypt_time_ms=("decrypt_time_ms", "mean"),
            avg_input_size_bytes=("input_size_bytes", "mean"),
            avg_output_size_bytes=("output_size_bytes", "mean"),
            avg_overhead_ratio=("overhead_ratio", "mean")
        ).reset_index()
    else:
        summary_report = pd.DataFrame()

    os.makedirs(output_dir, exist_ok=True)
    report_csv_path = os.path.join(output_dir, "stage4_benchmark_report.csv")
    summary_report.to_csv(report_csv_path, index=False, encoding='utf-8-sig')
    
    # In báo cáo trực tiếp ra màn hình
    print("\n" + "="*70)
    print("BÁO CÁO HIỆU NĂNG VÀ GIẢI MÃ CHUẨN XÁC (STAGE 4 BENCHMARK)")
    print("="*70)
    if not summary_report.empty:
        print(summary_report.to_string(index=False))
    else:
        print("Không có bản ghi mã hóa hợp lệ nào được tìm thấy để thống kê.")
    print("="*80)
    print(f"[✓] Báo cáo chi tiết đã lưu tại: {report_csv_path}")
    
    return report_csv_path, summary_report

def stage_4_batch_benchmark(file_paths: list, rsa_private_key_bytes: bytes, output_dir: str = "stage4_report") -> list:
    """
    Hàm bọc Batch cho Stage 4: Nhận vào danh sách file đã mã hóa từ Stage 3,
    lần lượt giải mã, đo benchmark và trả về danh sách đường dẫn các file báo cáo (report).
    """
    report_file_paths = []
    
    if not file_paths:
        print("[!] Danh sách file đầu vào Stage 4 trống.")
        return report_file_paths

    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"[!] Không tìm thấy file an toàn: {file_path}")
            continue
            
        print(f"\n[i] Đang chạy benchmark cho file: {file_path}")
        
        # Gọi hàm xử lý gốc của Stage 4 (giả sử hàm gốc trả về report_path và summary_df)
        report_path, summary_df = stage_4_benchmark_and_show(
            stage3_file_path=file_path, 
            rsa_private_key_bytes=rsa_private_key_bytes, 
            output_dir=output_dir
        )
        
        if report_path:
            report_file_paths.append(report_path)
            
    print(f"\n[✓] Stage 4 hoàn tất toàn bộ! Đã tạo {len(report_file_paths)} báo cáo benchmark.")
    return report_file_paths  # Trả về danh sách link báo cáo