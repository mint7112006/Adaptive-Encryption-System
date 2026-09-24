import os
import zipfile
import time
import easyocr
import ssl
import cv2
import urllib.request
import pandas as pd
import numpy as np
from typing import Union, IO, Generator, Tuple
from PIL import Image, UnidentifiedImageError

# ----------------------------------------------------------------------
# KHẮC PHỤC LỖI SSL CERTIFICATE KHI EASYOCR TẢI MODEL LẦN ĐẦU
# ----------------------------------------------------------------------
ssl._create_default_https_context = ssl._create_unverified_context
urllib.request.install_opener(
    urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
    )
)

# Danh sách 10 cột chuẩn dành cho Stage 2 & Stage 3
SYSTEM_COLUMNS = [
    "stt", "source_file", "data_type", "username", "password_raw",
    "pin_raw", "salt", "password_hash", "pin_encrypted", "is_secure"
]

########## Target 1: Đọc các file csv, jpg, zip #######################################

def ingest_csv(file_path: Union[str, IO], custom_filename: str = None) -> pd.DataFrame:
    encodings_to_try = ['utf-8-sig', 'utf-8', 'cp1258', 'latin1']
    df = None

    for enc in encodings_to_try:
        try:
            df = pd.read_csv(file_path, encoding=enc, sep=None, engine='python')
            break
        except Exception:
            if hasattr(file_path, 'seek'):
                file_path.seek(0)

    if df is not None and not df.empty:
        # Xử lý dọn dẹp ký tự BOM ẩn
        df.columns = df.columns.astype(str).str.replace('ï»¿', '', regex=False).str.strip()

        # 1. Đánh STT từ 1 đến N
        df['stt'] = range(1, len(df) + 1)

        # 2. Gán metadata nguồn và kiểu dữ liệu
        if custom_filename:
            df["source_file"] = custom_filename
        elif isinstance(file_path, str):
            df["source_file"] = os.path.basename(file_path)

        df["data_type"] = "CSV_RAW"

        # 3. Bổ sung các cột hệ thống chưa có với giá trị None
        for col in SYSTEM_COLUMNS:
            if col not in df.columns:
                df[col] = None  

        return df
    else:
        print(f"❌ Không thể đọc được file CSV bằng bất kỳ bảng mã nào!")
        return pd.DataFrame()


############################################################################################
# Khởi tạo EasyOCR reader 1 lần duy nhất ở cấp module
reader = easyocr.Reader(['vi', 'en'], gpu=True)
def preprocess_image_for_ocr(img_pil: Image.Image) -> np.ndarray:
    """
    Tiền xử lý ảnh giúp EasyOCR đọc chuẩn font Tiếng Việt và số:
    - Phóng to ảnh nhẹ nếu chữ quá nhỏ
    - Tăng độ tương phản và sắc nét
    """
    # Chuyển sang OpenCV format (BGR)
    img_cv = cv2.cvtColor(np.array(img_pil.convert("RGB")), cv2.COLOR_RGB2BGR)
    
    # Chuyển ảnh xám
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    
    # Resize phóng to 1.5 lần nếu ảnh nhỏ để EasyOCR soi rõ nét chữ
    h, w = gray.shape[:2]
    if w < 1500:
        gray = cv2.resize(gray, (int(w * 1.5), int(h * 1.5)), interpolation=cv2.INTER_CUBIC)
        
    # Tăng độ tương phản bằng CLAHE
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    
    return enhanced

def ingest_jpg(file_path: Union[str, IO], custom_filename: str = None) -> pd.DataFrame:
    if isinstance(file_path, str):
        file_name = os.path.basename(file_path)
    else:
        file_name = custom_filename if custom_filename else "unknown_image.jpg"

    default_row = {
        "stt": 1, "source_file": file_name, "data_type": "IMAGE_ERROR",
        "username": f"img_err_{file_name}", "password_raw": None,
        "pin_raw": None, "salt": None, "password_hash": None,
        "pin_encrypted": None, "is_secure": None
    }

    try:
        with Image.open(file_path) as img:
            img.verify()
    except (UnidentifiedImageError, OSError, Exception):
        default_row["data_type"] = "IMAGE_CORRUPTED"
        return pd.DataFrame([default_row])

    try:
        if hasattr(file_path, 'seek'):
            file_path.seek(0)

        with Image.open(file_path) as img:
            # Tiền xử lý ảnh nâng cao độ tương phản
            processed_img = preprocess_image_for_ocr(img)
            


        results = reader.readtext(
            processed_img,
            detail=0,
            paragraph=True,       # Nhóm các dòng bản in gần nhau thành đoạn văn chuẩn
            contrast_ths=0.1,     # Giảm ngưỡng tương phản để nhận diện chữ mờ
            adjust_contrast=0.5   # Tự động chỉnh độ tương phản khi quét
        )

        if results:
            default_row["data_type"] = "IMAGE_OCR"
            default_row["username"] = f"img_ocr_{file_name}"
            default_row["password_raw"] = " ".join(results)
        else:
            default_row["data_type"] = "IMAGE_METADATA"
            default_row["username"] = f"img_meta_{file_name}"
            default_row["password_raw"] = None

    except Exception:
        default_row["data_type"] = "IMAGE_ERROR"
        default_row["username"] = f"img_err_{file_name}"

    return pd.DataFrame([default_row])


############################################################################################

def process_file_stream(file_path: str) -> Generator[Tuple[str, pd.DataFrame], None, None]:
    if not os.path.exists(file_path):
        print(f"❌ File không tồn tại: {file_path}")
        return

    file_name = os.path.basename(file_path)
    ext = os.path.splitext(file_name)[1].lower()

    if ext == '.csv':
        df = ingest_csv(file_path)
        if not df.empty:
            yield file_name, df

    elif ext in ['.jpg', '.jpeg', '.png']:
        df = ingest_jpg(file_path)
        if not df.empty:
            yield file_name, df

    elif ext == '.zip':
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                for inner_file in z.namelist():
                    if inner_file.endswith('/') or inner_file.startswith('__MACOSX') or inner_file.startswith('.'):
                        continue

                    inner_ext = "." + inner_file.split(".")[-1].lower()
                    virtual_path = f"{file_name}/{inner_file}"

                    if inner_ext == '.csv':
                        with z.open(inner_file) as f:
                            df = ingest_csv(f, custom_filename=virtual_path)
                            if not df.empty:
                                yield virtual_path, df

                    elif inner_ext in ['.jpg', '.jpeg', '.png']:
                        with z.open(inner_file) as f:
                            df = ingest_jpg(f, custom_filename=virtual_path)
                            if not df.empty:
                                yield virtual_path, df

        except Exception as e:
            print(f"❌ Lỗi khi đọc file ZIP {file_name}: {e}")


# ----------------------------------------------------------------------
# RUNNER XUẤT RA THƯ MỤC OUTPUT_DATA
# ----------------------------------------------------------------------
def run_stage_1(input_path: str, output_dir: str = "output_data"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"🚀 Bắt đầu Stage 1 cho file: {input_path}")
    
    for virtual_path, df_result in process_file_stream(input_path):
        # Tạo tên file không bị trùng đè khi có thư mục con trong ZIP
        safe_name = virtual_path.replace('/', '_').replace('\\', '_')
        clean_name = os.path.splitext(safe_name)[0]
        out_file = os.path.join(output_dir, f"stage1_{clean_name}.csv")

        # Xuất ra file CSV
        df_result.to_csv(out_file, index=False, encoding='utf-8-sig', na_rep='None')
        print(f"  [✓] Đã xuất file: {out_file} ({len(df_result)} dòng)")

if __name__ == "__main__":
    # Điền file test ở đây
    input_file = input("Nhập đường dẫn file cần xử lý: ").strip(' "\'')
    run_stage_1(input_file, output_dir="output_data")