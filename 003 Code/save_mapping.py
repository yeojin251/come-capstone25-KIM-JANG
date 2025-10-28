import os
import sys
import json
import shutil

def save_mapping_from_file(user_id, source_path):
    base_dir = os.path.dirname(os.path.abspath(__file__))  # 현재 스크립트 기준
    print(base_dir)  # 디버깅용

    # 파일이 실제로 존재하는지 확인
    if not os.path.isfile(source_path):
        print(f"파일이 존재하지 않습니다: {source_path}")
        return

    print(os.getcwd())
    # 디렉토리 생성
    target_dir = os.path.join(base_dir, "encryption-client", user_id)
    os.makedirs(target_dir, exist_ok=True)

    # 대상 경로
    target_path = os.path.join(target_dir, "ascii_mapping.json")

    # 파일 복사
    shutil.copy(source_path, target_path)
    print(f"{target_path}로 ascii 매핑 파일이 저장되었습니다.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("사용법: python3 save_mapping.py [user_id] [ascii_mapping.json 경로]")
    else:
        user_id = sys.argv[1]
        json_path = sys.argv[2]
        save_mapping_from_file(user_id, json_path)
