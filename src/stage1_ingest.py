import os
import zipfile
import time
import easyocr
import pandas as pd
import numpy as np
from typing import Union, IO
from PIL import Image, UnidentifiedImageError
from tqdm import tqdm


########## Target 1: Đọc các file csv, jpg, zip #######################################
def ingest_csv(file_path: Union[str, IO]) -> pd.DataFrame:
# Danh sách các bảng mã sắp xếp theo độ ưu tiên giảm dần
    encodings_to_try = ['utf-8-sig', 'utf-8', 'cp1258', 'latin1']

    df = None

    for enc in encodings_to_try:
        try:
            # Thử đọc file với bảng mã hiện tại
            df = pd.read_csv(file_path, encoding=enc, sep = None, engine = 'python')
            print(f"Đọc file thành công bằng bảng mã: {enc}")
            break  # Nếu thành công thì thoát vòng lặp ngay
        except UnicodeDecodeError:
            print(f"Thất bại với bảng mã: {enc}. Đang thử bảng mã tiếp theo...")
            if hasattr(file_path, 'seek'):
                file_path.seek(0)            # tua ngược để thử các encoding phía sau

    # Kiểm tra kết quả sau khi thử hết danh sách
    if df is not None:
        # Xử lý dọn dẹp ký tự rác ẩn ï»¿ (BOM) ở tên cột nếu chẳng may rơi vào latin1
        df.columns = df.columns.str.replace('ï»¿', '', regex=False)
    
        # Hiển thị thử dữ liệu
        return df
    else:
        print("Không thể đọc được file bằng bất kỳ bảng mã phổ biến nào! Gửi lại file.")
        return pd.DataFrame()
 
############################################################################################
# Khởi tạo EasyOCR reader 1 lần duy nhất ở cấp module (global) (Tránh load lại Model mỗi khi gọi hàm)
# gpu=False nếu chạy trên CPU, gpu=True nếu máy có GPU NVIDIA
reader = easyocr.Reader(['vi'], gpu=False)    
def ingest_jpg(file_path: str, custom_filename: str = None) -> pd.DataFrame:
    # Nếu file_input là chuỗi đường dẫn, lấy tên file từ ổ cứng. 
    # Nếu là luồng byte từ ZIP, ta dùng tên file truyền từ ngoài vào qua custom_filename.
    # lấy tên file và đuôi mở rộng
    if isinstance(file_path, str):
        file_name = os.path.basename(file_path)
    else:
        file_name = custom_filename if custom_filename else "unknown_image.jpg"

     # Khởi tạo schema mặc định chống trùng lặp code
    default_row = {
        "stt": None, "source_file": file_name, "data_type": "IMAGE_ERROR",
        "username": f"img_err_{file_name}", "password_raw": None,
        "pin_raw": None, "salt": None, "password_hash": None,
        "pin_encrypted": None, "is_secure": None
    }

    # BƯỚC 1: Kiểm tra tính hợp lệ cấu hình ảnh bằng Pillow
    try:
        with Image.open(file_path) as img:
            img.verify() # Kiểm tra file có bị hỏng cấu trúc không
    except (UnidentifiedImageError, OSError, Exception):
        # File ảnh lỗi cấu trúc, giả mạo đuôi hoặc không đọc được hoàn toàn
        default_row["data_type"] = "IMAGE_CORRUPTED"
        return pd.DataFrame([default_row])

    # BƯỚC 2: Mở lại ảnh an toàn và chuyển dữ liệu sang EasyOCR xử lý
    try:
        # tua ngược
        if hasattr(file_path, 'seek'):
            file_path.seek(0)
        
        with Image.open(file_path) as img:
            # Chuyển ảnh sang định dạng RGB và ép Pillow load toàn bộ pixel vào RAM
            img = img.convert("RGB")
            img.load()
            
            # Chuyển đối tượng Pillow thành mảng Numpy để truyền vào EasyOCR an toàn 100%
            img_array = np.array(img)
            
        # Gọi EasyOCR bằng mảng dữ liệu trong RAM (Không lo bị lock file ổ cứng)
        results = reader.readtext(img_array, detail=0)
        
        if results:
            # 1. Ảnh chứa chữ (Hóa đơn, chứng từ, đoạn text...)
            default_row["data_type"] = "IMAGE_OCR"
            default_row["username"] = f"img_ocr_{file_name}"
            default_row["password_raw"] = " ".join(results)
        else:
            # 2. Ảnh không chứa chữ (Phong cảnh, ảnh trống...)
            default_row["data_type"] = "IMAGE_METADATA"
            default_row["username"] = f"img_meta_{file_name}"
            default_row["password_raw"] = None

    except Exception as e:
        # Xử lý các lỗi phát sinh trong quá trình OCR (Ví dụ: Ảnh quá lớn gây tràn RAM)
        default_row["data_type"] = "IMAGE_ERROR"
        default_row["username"] = f"img_err_{file_name}"
        default_row["password_raw"] = None

    # Trả về 1 dòng DataFrame chuẩn Schema của bạn
    return pd.DataFrame([default_row])   
 
############################################################################################   
def ingest_zip(file_path: str) -> pd.DataFrame:
    dfs = []
    zip_name = os.path.basename(file_path)

    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            for filename in z.namelist():
                # Bỏ qua thư mục rác hoặc file hệ thống của MacOS/Windows
                if filename.endswith('/') or filename.startswith('__MACOSX'):
                    continue
                
                ext = "." + filename.split(".")[-1].lower()
                #z.open(filename) để biến nó thành một luồng dữ liệu trên RAM và truyền thẳng đối tượng đó vào hàm.
                # TRƯỜNG HỢP 1: File CSV trong ZIP
                if ext == '.csv':
                    with z.open(filename) as f:
                    # Truyền trực tiếp luồng byte 'f' vào hàm ngoài
                        df = ingest_csv(f)
        
                    if not df.empty:
                        df['source_file'] = f"{zip_name}/{filename}"
                    dfs.append(df)

                # TRƯỜNG HỢP 2: File Ảnh (JPG/PNG) trong ZIP
                elif ext in ['.jpg', '.jpeg', '.png']:
                    with z.open(filename) as f:
                        # Truyền luồng byte 'f' và tên file ảo trong zip vào hàm ngoài
                        df = ingest_jpg(f, custom_filename=filename)
                    if not df.empty:
                        df['source_file'] = f"{zip_name}/{filename}"
                        dfs.append(df)                   

    except Exception as e:
        print(f"Lỗi khi đọc file ZIP {zip_name}: {e}")

    # Gộp tất cả DataFrame con tìm được trong ZIP thành 1 DataFrame duy nhất
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        return pd.DataFrame()    
    
########## Target 2: Cấu trúc bảng ####################################################

########## Target 3: Làm sạch & Kiểm soát Lỗi Dữ liệu #################################


########## Target 4: Trực quan hóa Tiến trình #########################################


########## Target 5: Đầu ra Chuẩn cho Stage 2 #########################################

def process_single_file(file_path: str) -> pd.DataFrame:
    """Router nhận diện đuôi file và gọi hàm ingest tương ứng"""
    ext = os.path.splitext(file_path)[1].lower()
    
    # 1. Trường hợp file riêng lẻ là CSV
    if ext == '.csv':
        return ingest_csv(file_path)
    
    # 2. Trường hợp file riêng lẻ là Ảnh (JPG/PNG)
    elif ext in ['.jpg', '.jpeg', '.png']:
        return ingest_jpg(file_path)
    
    # 3. Trường hợp file Nén ZIP (chứa các file CSV/JSON bên trong)
    elif ext == '.zip':
        return ingest_zip(file_path)
    
    else:
        print(f"Định dạng file không hỗ trợ: {file_path}")
        return pd.DataFrame()


def run_stage1_pipeline(input_dir="./input_data", output_dir="./output_stage1"):
    # ... (Code nạp các file và gộp thành final_df) ...
    
    # KHI ĐÃ CÓ FINAL_DF HOÀN CHỈNH:
    if not final_df.empty:
        # Tạo thư mục output nếu chưa có
        os.makedirs(output_dir, exist_ok=True)
        
        # Lưu file sao lưu Stage 1
        output_file_path = os.path.join(output_dir, "stage1_output_cleaned.csv")
        final_df.to_csv(output_file_path, index=False, encoding='utf-8-sig')
        print(f"Đã lưu bản sao dữ liệu Stage 1 tại: {output_file_path}")
        
    return final_df