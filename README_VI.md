# GOST-NIZKP — cài đặt Python dùng PyCryptodome

Bản cài đặt tham chiếu cho lược đồ trong `GOST_NIZKP_Informatics_Automation.zip`, dựa trên mục 3 và mục 4.2 của bài báo. Toàn bộ comment và docstring trong mã Python được viết bằng tiếng Anh.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên. Đã kiểm tra bằng Python 3.12 và PyCryptodome 4.3.0.

```bash
python -m venv .venv
```

Kích hoạt môi trường trên Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Trên Linux/macOS:

```bash
source .venv/bin/activate
```

Sau đó, chạy trong thư mục chứa `demo.py`:

```bash
python -m pip install -r requirements.txt
python demo.py
python -m unittest discover -s tests -v
```

Ví dụ in ra khóa công khai, kích thước chứng minh 64 byte, kết quả xác thực lần đầu và từ chối khi phát lại, dùng kết nối khác hoặc khóa bị thu hồi. Khóa bí mật và nonce không được in ra. Mật khẩu trong demo là dữ liệu công khai để minh họa; không sử dụng cho thông tin thật.

## Các tệp

| Tệp | Chức năng |
|---|---|
| `gost_nizkp/core.py` | Tham số, phép toán điểm, mã hóa chuẩn tắc, sinh khóa, tạo và kiểm tra chứng minh |
| `gost_nizkp/service.py` | Ví dụ đăng ký, quay vòng/thu hồi khóa, kiểm tra thời gian và chống phát lại nguyên tử trong một tiến trình |
| `gost_nizkp/vault.py` | Lớp bảo vệ khóa cục bộ tùy chọn: scrypt và AES-256-GCM |
| `demo.py` | Ví dụ đầy đủ chạy cục bộ |
| `tests/test_protocol.py` | 25 phép kiểm thử chức năng, dữ liệu sai và điều kiện biên |
| `tests/vector.json` | Vector cố định cho chính định dạng NIZKP này; khóa và nonce đều là dữ liệu kiểm thử công khai |
| `test_results.txt` | Kết quả chạy kiểm thử tại thời điểm bàn giao |

## Đối chiếu với bài báo

| Thành phần | Mã nguồn |
|---|---|
| Điều kiện p < n, G khác điểm vô cực, nG = O | `validate_domain()` |
| Sinh d ngẫu nhiên trong [1,n−1], P_A = dG | `generate_keypair()` |
| Kiểm tra điểm thuộc đường cong và nhóm con | `validate_public_key()` và `import_public_key()` |
| Ngữ cảnh m gồm phiên bản, suite, tài khoản, dịch vụ, phiên bản khóa, thời gian, liên kết phiên | `Context.to_bytes()` |
| h = H(Encode(tag,m,r,P_A)), h khác 0 | `challenge()` |
| k ngẫu nhiên độc lập; r = x(kG) mod n; r khác 0 | `prove()` |
| z = (rd + kh) mod n | `prove()` |
| T = h⁻¹(zG − rP_A), T khác O và x(T) mod n = r | `verify()` |
| Cho phép z = 0 theo giao thức trong bài | `Proof` và `verify()` |
| Thời gian hợp lệ, trạng thái khóa, liên kết kết nối, chặn phát lại | `AuthenticationService.authenticate()` |

`verify()` chỉ kiểm tra tính hợp lệ mật mã. Nó không tự quyết định thời gian hay quyền truy cập. Dùng lớp dịch vụ để minh họa các kiểm tra ứng dụng và vẫn phải thực hiện phân quyền sau khi xác thực thành công.

## PyCryptodome được sử dụng ở đâu?

- `Crypto.Hash.SHA256`: ánh xạ challenge và định danh chống phát lại.
- `Crypto.Random.get_random_bytes`: sinh khóa, nonce, salt và nonce AES-GCM.
- `Crypto.Util.number.inverse`, `isPrime`: nghịch đảo và kiểm tra nguyên tố.
- `Crypto.Protocol.KDF.scrypt`: bảo vệ khóa bằng mật khẩu tại thiết bị.
- `Crypto.Cipher.AES`: mã hóa có xác thực AES-GCM cho vault.

API ECC của PyCryptodome không hỗ trợ bộ đường cong GOST trong bài. Vì vậy phép cộng/nhân điểm được cài đặt bằng Python với chính bộ tham số RFC 5832, mục 7, đã dùng trong bảng 2 của bản thảo. Không thay đường cong bằng P-256, không sửa registry nội bộ của thư viện và không gọi ECDSA để giả lập lược đồ. Vector kiểm thử độc lập của RFC được dùng để kiểm tra phép toán điểm và phương trình đại số.

## Những lựa chọn cụ thể hóa từ bài báo

Bản thảo định nghĩa một giao diện hash-to-scalar và mã hóa chuẩn tắc, chưa định nghĩa định dạng trao đổi byte hoàn chỉnh. Mã nguồn chốt một cấu hình thử nghiệm như sau:

1. Suite: `GOST-NIZKP-RFC5832-TEST-SHA256-v1`; protocol: `GOST-NIZKP-v1`.
2. Mỗi trường TLV là `type:u8 || length:u32be || value`. Các số nguyên dùng big-endian. Không thực hiện chuyển đổi Unicode ngầm định. Nếu dùng chuỗi, hai bên tự thống nhất UTF-8 trước khi gọi API.
3. `m`: trường 1 protocol, 2 suite, 3 account ID, 4 verifier ID, 5 credential version, 6 timestamp, 7 channel binding. Phiên bản khóa bắt đầu từ 1; timestamp là Unix time tính bằng giây. Hai số được mã hóa 8 byte không dấu. ID dài 1–256 byte; binding dài đúng 32 byte.
4. Đầu vào challenge: trường 1 `GOST-NIZKP/challenge`, 2 `m`, 3 `r` dạng 32 byte, 4 khóa công khai nén.
5. Hash-to-scalar: SHA-256 trên TLV gồm trường 1 `GOST-NIZKP/hash-to-scalar/SHA256/v1`, 2 đầu vào challenge, 3 counter 4 byte bắt đầu từ 0. Đọc đủ 256 bit; nhận nếu 1 ≤ h < n, nếu không tăng counter. Không lấy digest modulo n vì gây sai lệch phân phối. Với bộ tham số này n dài 256 bit.
6. Khóa công khai: 33 byte kiểu SEC1 nén (`02/03 || x`); chứng minh: `r:32-byte || z:32-byte`. Không chấp nhận độ dài khác hoặc scalar ngoài miền. Đây là định dạng riêng của cấu hình nghiên cứu, không phải định dạng chữ ký GOST tiêu chuẩn.
7. Giới hạn thông điệp mật mã là 4096 byte. API dịch vụ dựng lại thông điệp từ dữ liệu đã kiểm tra thay vì nhận trực tiếp một ngữ cảnh tùy ý từ client.
8. Cửa sổ mẫu: quá khứ 60 giây, tương lai 5 giây; có thể cấu hình. Mục chống phát lại được giữ đến sau giây hợp lệ cuối cùng. Kho đầy thì từ chối yêu cầu mới, không xóa mục còn hiệu lực. Đồng hồ quay lùi thì từ chối cho đến khi bắt kịp mốc đã quan sát.

SHA-256 là lựa chọn triển khai cho giao diện H, không phải hàm băm GOST. Cài đặt hàm băm cụ thể không biến chứng minh ROM thành chứng minh trong mô hình chuẩn.

## Vault mật khẩu tùy chọn

Khóa d luôn được sinh ngẫu nhiên độc lập. `seal()` chỉ mã hóa khóa đã có; không dùng mật khẩu để tính d. `unseal()` kiểm tra xác thực trước khi trả lại khóa.

Cấu hình vault phiên bản 1: scrypt N=32768, r=8, p=1; khóa AES 32 byte; salt ngẫu nhiên 16 byte; nonce GCM ngẫu nhiên 12 byte; tag 16 byte. Định dạng là `GNZV || 01 || salt || nonce || compressed_public_key || encrypted_secret || tag`. Header, suite và chủ sở hữu được ràng buộc bằng AAD. Chi phí KDF được cố định bởi phiên bản để dữ liệu độc hại không yêu cầu lượng bộ nhớ/tính toán tùy ý.

Bài báo gợi ý Argon2id cho một lớp bảo vệ mật khẩu riêng. Ví dụ này dùng scrypt vì có sẵn trong PyCryptodome; nó không phải cài đặt Argon2id và không thay đổi giao thức chứng minh. Mất vault vẫn cho phép dò mật khẩu offline; phải đánh giá tham số trên thiết bị thực tế. Các hàm chỉ trả về bytes, không tự ghi khóa hay mật khẩu ra đĩa.

## Phạm vi sử dụng

Đây là bản cài đặt tham chiếu để nghiên cứu và tái hiện phương trình, chưa phải thư viện triển khai sản xuất:

- Bộ tham số được RFC xác định là tham số kiểm thử. Chưa cung cấp bộ tham số triển khai đã được thẩm định độc lập.
- Phép toán điểm và số nguyên Python có thời gian thực thi phụ thuộc dữ liệu. Chưa chống timing, cache, fault hoặc rò rỉ bộ nhớ; Python không bảo đảm xóa sạch bản sao khóa/nonce. Không suy ra độ an toàn sản xuất từ việc các kiểm thử đều thành công.
- `enroll_authorized`, `rotate_authorized`, `revoke_authorized` là giao diện quản trị tin cậy. Ứng dụng phải xác minh danh tính và phân quyền bên ngoài trước khi gọi. Chúng không phải endpoint đăng ký công khai.
- Chưa tích hợp TLS. `trusted_channel_binding` phải được lớp vận chuyển lấy từ kết nối đã xác thực, chẳng hạn `tls-exporter` theo RFC 9266. Không lấy từ JSON hoặc header do client gửi. Giá trị ngẫu nhiên trong demo chỉ mô phỏng hai bên có cùng binding; nó không cung cấp TLS. Không chấp nhận xác thực qua early data. Kết quả thành công chỉ gắn với kết nối đang xử lý.
- Trạng thái tài khoản và replay trong ví dụ là RAM của một tiến trình. Khởi động lại làm mất trạng thái. Nhiều máy chủ cần kho lưu trữ bền vững, nhất quán và giao dịch nguyên tử cho trạng thái/phiên bản khóa và chấp nhận chứng minh. RLock chỉ bảo đảm đồng thời giữa các luồng dùng cùng đối tượng trong một tiến trình.
- Chưa có giao diện mạng, quản lý certificate, quy trình khôi phục danh tính, rate limit toàn hệ thống, audit log hoặc phân quyền dữ liệu nghiệp vụ.
- Các phép kiểm tra mô phỏng oracle, z=0 và trích xuất hai nhánh dấu chỉ nằm trong test. API `prove()` không nhận nonce tùy chọn; luôn sinh nonce mới. Vector công khai không được dùng làm khóa hoặc nonce thực.

## Kết quả kiểm thử

25 tests đã chạy thành công. Bao phủ vector RFC độc lập, vòng lặp sinh/kiểm tra, điểm sai, scalar/encoding sai, sửa từng trường ngữ cảnh, sửa chứng minh, z=0, điểm vô cực, rejection sampling, trích xuất hai dấu, đại số simulator, giới hạn đầu vào, replay đồng thời chỉ chấp nhận một lần, biên timestamp, quay vòng/thu hồi, kho replay đầy, đồng hồ quay lùi và vault bị sửa/sai mật khẩu.

Đây là kiểm thử chức năng và hồi quy, không phải kiểm chứng hình thức, đánh giá side channel hay benchmark của bài báo. `test_results.txt` ghi thời gian chạy bộ test, không phải thời gian xác thực của hệ thống thực tế.

## Tài liệu API và tham số

- PyCryptodome ECC: https://www.pycryptodome.org/src/public_key/ecc
- SHA-256: https://www.pycryptodome.org/src/hash/sha256
- Utilities: https://www.pycryptodome.org/src/util/util
- KDF: https://www.pycryptodome.org/src/protocol/kdf
- AES-GCM: https://www.pycryptodome.org/src/cipher/modern
- Tham số/vector: https://www.rfc-editor.org/rfc/rfc5832 — mục 7
- Channel binding: https://www.rfc-editor.org/rfc/rfc9266
