import random
import secrets
import os
import random
import pandas as pd
from faker import Faker
import time

# Bảng mã Tỉnh / Thành phố 
PROVINCE_CODES = {
    "01": "Thành phố Hà Nội",
    "04": "Tỉnh Cao Bằng",
    "08": "Tỉnh Tuyên Quang",
    "11": "Tỉnh Điện Biên",
    "12": "Tỉnh Lai Châu",
    "14": "Tỉnh Sơn La",
    "15": "Tỉnh Lào Cai",
    "19": "Tỉnh Thái Nguyên",
    "20": "Tỉnh Lạng Sơn",
    "22": "Tỉnh Quảng Ninh",
    "24": "Tỉnh Bắc Ninh",
    "25": "Tỉnh Phú Thọ",
    "31": "Thành phố Hải Phòng",
    "33": "Tỉnh Hưng Yên",
    "37": "Tỉnh Ninh Bình",
    "38": "Tỉnh Thanh Hóa",
    "40": "Tỉnh Nghệ An",
    "42": "Tỉnh Hà Tĩnh",
    "44": "Tỉnh Quảng Trị",
    "46": "Thành phố Huế",
    "48": "Thành phố Đà Nẵng",
    "51": "Tỉnh Quảng Ngãi",
    "52": "Tỉnh Gia Lai",
    "56": "Tỉnh Khánh Hòa",
    "66": "Tỉnh Đắc Lắc",
    "68": "Tỉnh Lâm Đồng",
    "75": "Tỉnh Đồng Nai",
    "79": "Thành phố Hồ Chí Minh",
    "80": "Tỉnh Tây Ninh",
    "82": "Tỉnh Đồng Tháp",
    "86": "Tỉnh Vĩnh Long",
    "91": "Tỉnh An Giang",
    "92": "Thành phố Cần Thơ",
    "96": "Tỉnh Cà Mau"
}

def get_gender_century_code(gender: str, birth_year: int) -> str:
    """
    Tính mã giới tính + thế kỷ dựa theo quy định:
    - Thế kỷ 20 (1900-1999): Nam = 0, Nữ = 1
    - Thế kỷ 21 (2000-2099): Nam = 2, Nữ = 3
    """
    if 1900 <= birth_year <= 1999:
        return "0" if gender == "Nam" else "1"
    elif 2000 <= birth_year <= 2099:
        return "2" if gender == "Nam" else "3"
    return "0"

def generate_vietnam_cccd(gender: str, birth_year: int):
    """
    Sinh CCCD chuẩn định dạng 12 số và trả về kèm Nơi sinh tương ứng
    """
    # 1. Mã Tỉnh/Thành phố (2 chữ số sau số 0)
    prov_code, prov_name = secrets.choice(list(PROVINCE_CODES.items()))
    
    # 2. Mã Giới tính & Thế kỷ (1 chữ số)
    gender_code = get_gender_century_code(gender, birth_year)
    
    # 3. 2 số cuối năm sinh (2 chữ số)
    year_code = str(birth_year)[-2:]
    
    # 4. 6 số ngẫu nhiên ngẫu nhiên cuối cùng (6 chữ số)
    random_suffix = ''.join(secrets.choice("0123456789") for _ in range(6))
    
    # Ghép lại thành CCCD 12 số chuẩn
    cccd_number = f"0{prov_code}{gender_code}{year_code}{random_suffix}"
    
    return cccd_number, prov_name
#####################################################################
def generate_clean_name(gender: str) -> str:
    """
    Sinh Họ và Tên chuẩn Việt Nam
    """
    # 1. Lấy Họ ngẫu nhiên
    last_name = fake.last_name()
    
    # 2. Lấy Tên đệm + Tên theo đúng giới tính
    if gender == "Nam":
        first_name = fake.first_name_male()
    else:
        first_name = fake.first_name_female()
        
    # Ghép lại thành Họ và Tên sạch
    return f"{last_name} {first_name}"

#####################################################################
# Danh sách một số tên đường/phố phổ biến ở Việt Nam
STREET_NAMES = [
    "Nguyễn Trãi", "Lê Lợi", "Trần Hưng Đạo", "Giải Phóng", "Cầu Giấy",
    "Nguyễn Huệ", "Đại Cồ Việt", "Nguyễn Chí Thanh", "Hoàng Hoa Thám",
    "Phạm Văn Đồng", "Quang Trung", "Hai Bà Trưng", "Lê Duẩn", "Trường Chinh"
]

# Danh sách Phường / Xã mẫu
WARD_NAMES = [
    "Phường Bách Khoa", "Phường Hàng Bài", "Phường Dịch Vọng", "Phường Bến Nghé",
    "Phường Lăng Cô", "Phường Thạch Thang", "Phường Tân Định", "Phường An Khánh"
]

def generate_vietnam_address(province_name: str) -> str:
    """
    Sinh địa chỉ 
    """
    house_num = secrets.randbelow(300) + 1  # Sinh số nhà từ 1 đến 300
    street = secrets.choice(STREET_NAMES)
    ward = secrets.choice(WARD_NAMES)
    
    # Ghép thành địa chỉ chuẩn dạng: Số 45, Đường Nguyễn Trãi, Phường Bách Khoa, Thành phố Hà Nội
    return f"Số {house_num}, Đường {street}, {ward}, {province_name}"
#####################################################################
# Cập nhật danh sách bổ sung đầu 081 của VinaPhone
VN_PREFIXES = [
    # VinaPhone
    "091", "094", "084", "088", "083", "084", "085", "081", "082",
    # Viettel
    "032", "033", "034", "035", "036", "037", "038", "039","086","096","097","098",
    # MobiFone
    "090", "093", "089", "070", "079", "076", "077", "078",
    # Vietnamobile
    "056", "058", "052", "092"
]

def generate_vietnam_phone() :
    """
    Sinh số điện thoại di động Việt Nam chuẩn 10 chữ số
    Dạng: 098xxxxxxx, 091xxxxxxx...
    """
    prefix = secrets.choice(VN_PREFIXES)
    suffix = ''.join(secrets.choice("0123456789") for _ in range(7))
    return prefix+suffix
#####################################################################

fake = Faker('vi_VN')

def generate_pii_dataset(num_records):
    data = []
    
    for i in range(1, num_records + 1):
        # Giả lập giới tính và ngày sinh trước
        gender = random.choice(["Nam", "Nu"])
        dob_date = fake.date_of_birth(minimum_age=18, maximum_age=65)
        birth_year = dob_date.year
        
        # Sinh CCCD và Nơi sinh theo chuẩn
        cccd, birth_place = generate_vietnam_cccd(gender, birth_year)
        
        record = {
            "Stt": i,
            "Tên": generate_clean_name(gender),
            "Giới tính": "Nam" if gender == "Nam" else "Nữ",
            "Ngày sinh": str(dob_date),
            "Nơi sinh": birth_place,                   # Nơi sinh khớp với 3 số đầu CCCD
            "CCCD": cccd,                                  # CCCD chuẩn logic 12 số
            "Sdt": generate_vietnam_phone(),
            "email": f"{fake.user_name()}@gmail.com",
            "Địa chỉ nhà": generate_vietnam_address(birth_place),
            "Thẻ tín dụng": fake.credit_card_number()
        }
        data.append(record)
    
    df = pd.DataFrame(data)
    
    output_dir = './input_data'
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_filename = f"fake_pii_{timestamp}.csv"
    output_path = os.path.join(output_dir, output_filename)
    df.to_csv(output_path, index=False, encoding='utf-8-sig')


if __name__ == "__main__":
    generate_pii_dataset(2)