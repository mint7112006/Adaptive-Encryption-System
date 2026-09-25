import os
import time
import joblib
import pandas as pd
from Crypto.PublicKey import RSA

# Import hàm thực thi từ các file
from src.stage1_ingest import run_stage_1
from src.stage2_extract import stage_2_process_with_dt
from src.stage3_crypto import stage_3_batch_enforcement
from src.stage4_visualize import stage_4_batch_benchmark

def generate_or_load_rsa_keys():
    """Hàm phụ trợ sinh cặp khóa RSA-2048 cho toàn bộ pipeline"""
    key = RSA.generate(2048)
    return key.publickey().export_key(), key.export_key()

def main():
    print("=" * 80)
    print("   HỆ THỐNG XỬ LÝ VÀ BẢO VỆ DỮ LIỆU TỰ ĐỘNG (PII PIPELINE)")
    print("=" * 80)

    # 1. Nhập đường dẫn file thô đầu vào
    input_file = input("\nNhập đường dẫn file: ").strip(' "\'')

    if not input_file:
        print("Bạn chưa nhập đường dẫn. Chương trình kết thúc.")
        return

    if not os.path.exists(input_file):
        print(f"File không tồn tại tại đường dẫn: {input_file}")
        return

    # Khởi tạo cặp khóa RSA bất đối xứng cho toàn hệ thống
    print("\n[KEY_GEN] Đang khởi tạo cặp khóa RSA-2048 (Public/Private)...")
    pub_key_bytes, priv_key_bytes = generate_or_load_rsa_keys()

    # Tính thời gian bắt đầu chương trình
    start_time = time.time()

    # ------------------------------------------------------------------
    # GIAI ĐOẠN 1: BÓC TÁCH & CHUẨN HÓA DỮ LIỆU (STAGE 1)
    # ------------------------------------------------------------------
    print("\n[STAGE 1] Bắt đầu đọc và chuẩn hóa dữ liệu thô")
    stage1_outputs = run_stage_1(input_file, output_dir="output_data")

    if not stage1_outputs:
        print("Stage 1 không tạo ra file CSV nào hợp lệ. Pipeline dừng lại.")
        return

    print(f"\n[STAGE 1 HOÀN TẤT] Đã tạo {len(stage1_outputs)} file CSV trong 'output_data/':")
    for idx, path in enumerate(stage1_outputs, 1):
        print(f"   {idx}. {path}")
      
    # ------------------------------------------------------------------
    # GIAI ĐOẠN 2: TRÍCH XUẤT ĐẶC ĐIỂM & GÁN NHÃN (STAGE 2)
    # ------------------------------------------------------------------
    print("\n[STAGE 2] Bắt đầu nhận kết quả Stage 1 để gán nhãn loại mã hóa bảo mật")
    dt_model_path = "models/decision_tree_model.pkl"
    
    if not os.path.exists(dt_model_path):
        print(f"[!] Không tìm thấy mô hình Decision Tree tại '{dt_model_path}'.")
        return

    dt_model = joblib.load(dt_model_path)
    
    # Stage 2 trả về danh sách các file đã gán nhãn
    stage2_outputs = stage_2_process_with_dt(stage1_outputs, dt_model, output_dir="processed_data")

    if not stage2_outputs:
        print("Stage 2 không tạo ra file kết quả nào. Pipeline dừng lại.")
        return

    # ------------------------------------------------------------------
    # GIAI ĐOẠN 3: THI HÀNH MÃ HÓA BẢO MẬT (STAGE 3 - BATCH PROCESSING)
    # ------------------------------------------------------------------
    print("\n[STAGE 3] Bắt đầu thi hành mã hóa/bọc phong bì toàn bộ danh sách file từ Stage 2")
    stage3_secured_files = stage_3_batch_enforcement(
        file_paths=stage2_outputs, 
        rsa_public_key_bytes=pub_key_bytes, 
        output_dir="encrypt"
    )

    if not stage3_secured_files:
        print("[!] Stage 3 không tạo ra được file an toàn nào. Pipeline dừng lại.")
        return

        # ------------------------------------------------------------------
        # GIAI ĐOẠN 4: GIẢI MÃ & ĐO BENCHMARK (STAGE 4)
        # ------------------------------------------------------------------
        print("[STAGE 4] Bắt đầu giải mã, kiểm tra tính toàn vẹn và đo benchmark hiệu năng")
    stage4_reports = stage_4_batch_benchmark(
        file_paths=stage3_secured_files, 
        rsa_private_key_bytes=priv_key_bytes, 
        output_dir="report"
    )

    print(f"\n[PIPELINE HOÀN TẤT] Tổng số báo cáo benchmark thu được: {len(stage4_reports)}")

    total_time = time.time() - start_time
    print("\n" + "="*100)
    print(f"TOÀN BỘ PIPELINE ĐÃ CHẠY THÀNH CÔNG RỰC RỠ! (Thời gian: {total_time:.2f}s)")
    print(f"Tệp dữ liệu an toàn cuối cùng: {stage3_secured_files}")
    print(f"Báo cáo benchmark hiệu năng: {stage4_reports}")
    print("="*100)

if __name__ == "__main__":
    main()