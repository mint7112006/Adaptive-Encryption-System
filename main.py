import os
import time
import joblib

# Import hàm thực thi từ các file
from src.stage1_ingest import run_stage_1
from src.stage2_extract import stage_2_process_with_dt

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
    # Tính thời gian bắt đầu chương trình
    start_time = time.time()
    # ------------------------------------------------------------------
    # GIAI ĐOẠN 1: BÓC TÁCH & CHUẨN HÓA DỮ LIỆU (STAGE 1)
    # ------------------------------------------------------------------
    print("\n[STAGE 1] Bắt đầu đọc và chuẩn hóa dữ liệu thô")
    stage1_outputs = run_stage_1(input_file, output_dir="output_data")

    # Kiểm tra xem Stage 1 có xuất ra file nào không (nếu có thì stage1_outputs là danh sách đường dẫn)
    if not stage1_outputs:
        print("Stage 1 không tạo ra file CSV nào hợp lệ. Pipeline dừng lại.")
        return

    print(f"\n[STAGE 1 HOÀN TẤT] Đã tạo {len(stage1_outputs)} file CSV trong 'output_data/':")
    for idx, path in enumerate(stage1_outputs, 1):
        print(f"   {idx}. {path}")
      
        
    # ------------------------------------------------------------------
    # GIAI ĐOẠN 2: TRÍCH XUẤT ĐẶC ĐIỂM & MÃ HÓA/BẢO VỆ (STAGE 2)
    # ------------------------------------------------------------------
    print("\n[STAGE 2] Bắt đầu nhận kết quả Stage 1 để gán nhãn loại mã hóa bảo mật")
    # Load mô hình Decision Tree từ thư mục models/
    dt_model_path = "models/decision_tree_model.pkl"
    dt_model = joblib.load(dt_model_path)
    # Truyền trực tiếp danh sách đường dẫn file của Stage 1 làm đầu vào cho Stage 2
    stage2_outputs = stage_2_process_with_dt(stage1_outputs,dt_model ,output_dir="processed_data")

if __name__ == "__main__":
    main()       