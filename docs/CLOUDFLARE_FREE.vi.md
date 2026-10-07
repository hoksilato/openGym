# openGym trên Cloudflare Free (PWA iPhone)

Bản port dành cho một nhóm nhỏ khoảng 2–3 người. Dựa trên upstream `DuarteSantos8/openGym`
commit `1350409a7b15ff8ce5690c18b530cfba62d80f46` (v1.3.9). Node API và Docker upstream vẫn giữ nguyên.

**Tình trạng:** adapter được kiểm thử cục bộ bằng workerd/Miniflare, D1 và Durable Objects;
chưa triển khai lên tài khoản Cloudflare, chưa xác nhận CPU/quota thực tế của Free,
chưa thử Face ID, Safari standalone hay Web Push trên iPhone thật. PR là draft.
Không có thao tác tạo tài khoản, cấp quyền, tạo secret production, bật billing hoặc deploy trong thay đổi này.

## Kiến trúc và tính năng

- Static Assets phục vụ bản web Vite; chỉ `/api` và `/api/*` gọi Worker
- Worker chuyển tiếp sang một SQLite Durable Object (`OpenGym`, tên `opengym`)
- DO xử lý auth, JSON lớn, API và alarm; không đặt scrypt/WebAuthn/import 5 MiB vào CPU 10 ms của Free Worker
- D1 lưu user, passkey public key, invite, mã băm một lần, audit, subscription và dữ liệu tập
- State dùng manifest/revision và chunk nhỏ hơn giới hạn 2 MB/row. Một D1 transaction xuất bản
  version mới bằng CAS; `baseRev`, `_rev`, lỗi 409 + state hiện tại và metadata reset được giữ
- `GET /api/data/rev` chỉ đọc head. Workout đang tập vẫn ở thiết bị
- Mọi thao tác API/alarm vào một FIFO có giới hạn; không dựa vào Map để lưu auth hay timer
- Passkey, nhiều passkey, device-link, pairing, logout-all, disable, admin/invite/audit được giữ
- Password/email alias/reset bằng admin là tùy chọn, mặc định `PASSWORD_LOGIN=0`;
  nếu bật dùng scrypt upstream N=32768, r=8, p=1, không giảm độ mạnh để tiết kiệm CPU.
  Hash legacy tùy chỉnh cần trên64MiB working memory bị từ chối để giữ giới hạn DO128MiB;
  trường hợp đó cần reset password, không tự hạ tham số
- Rest countdown trong app vẫn dùng `endsAt`; push timer/reminder dùng DO alarm bền vững
- Media upload riêng và AI Coach tắt ở profile này. Không cần R2, model API, VPS hay container trả phí
- Giao diện giữ các ngôn ngữ upstream (hiện chưa có gói tiếng Việt); tài liệu hướng dẫn này bằng tiếng Việt
- Danh mục bài tập dạng text vẫn có; không tải/đóng gói lại bộ ảnh/video có quyền sử dụng chưa rõ
- Luồng sync được bổ sung kiểm tra UID để phản hồi cũ/account-switch không đưa dữ liệu người A sang B

Đây là cấu hình cho một instance nhỏ, không phải dịch vụ public nhiều người. DO đơn giúp quản lý
đồng bộ và CPU đơn giản; cần tách shard theo người dùng trước khi mở rộng đáng kể.

## Chuẩn bị cục bộ (không deploy)

Yêu cầu Node >=22 và npm. Từ root repo:

```sh
npm ci --prefix frontend
npm ci --prefix cloudflare
npm test --prefix cloudflare
npm run build --prefix cloudflare
```

`build` tạo frontend và chạy `wrangler deploy --dry-run`; **không upload/deploy**.
Không có Cloudflare credential trong repo. `cloudflare/.dev.vars` và `.wrangler` được gitignore.
Các khóa cố định trong test là fixture công khai chỉ để kiểm thử, tuyệt đối không dùng production.

Build flags:

- `VITE_EXERCISE_MEDIA=false` mặc định: thumbnail trung tính, không request bộ media bên ngoài
- Nếu có tài nguyên đã được phép dùng, có thể bật `VITE_EXERCISE_MEDIA=true` và đặt
  `VITE_IMG_BASE`/`VITE_GIF_BASE` theo adapter frontend hiện có
- `VITE_SOURCE_URL` mặc định trỏ source branch của fork; khi đổi nơi phát hành phải trỏ tới source
  tương ứng bản đang chạy để đáp ứng AGPL. Không xóa LICENSE/NOTICE

## Các bước operator phải chủ động thực hiện trước khi chạy thật

Các lệnh dưới đây là hướng dẫn, chưa được chạy. Chỉ thực hiện sau khi quyết định hostname và
cho phép thao tác trong tài khoản Cloudflare. Không bật Workers Paid hoặc đăng ký R2 cho profile này.

1. Chọn hostname HTTPS lâu dài. Sửa `cloudflare/wrangler.jsonc`:
   `ORIGIN=https://opengym.<subdomain>.workers.dev`, `RP_ID=opengym.<subdomain>.workers.dev`.
   RP ID không có scheme/port/path và không phải `workers.dev` chung. Tắt preview URLs
   để tránh đăng ký passkey trên hostname tạm. Đổi sang domain không liên quan cần đăng ký lại passkey
2. Trong tài khoản Free, tạo D1 và điền UUID trả về vào `database_id`:
   `cd cloudflare && npx wrangler d1 create opengym`
3. Áp dụng migrations: `npx wrangler d1 migrations apply opengym --remote`
4. Tạo secret ngẫu nhiên >=32 ký tự bằng công cụ riêng của operator; nhập qua
   `npx wrangler secret put SESSION_SECRET`. Không đặt secret trong vars, frontend, chat hoặc Git
5. Bootstrap một invite admin ngoài ứng dụng bằng D1 SQL. Dùng mã ngẫu nhiên >=128 bit của riêng
   operator thay cho placeholder dưới đây; tuyệt đối không dùng nguyên placeholder:

```sql
INSERT INTO invites(code,note,created,admin)
VALUES('REPLACE_WITH_PRIVATE_RANDOM_BOOTSTRAP_CODE','owner bootstrap',datetime('now'),1);
```

6. `npm run check:config` phải pass, sau đó build và chỉ deploy khi đã được cho phép:
   `npm run build && npx wrangler deploy`
7. Mở đúng hostname bằng Safari, đăng ký passkey với invite bootstrap. Chỉ invite đã seed
   `admin=1` mới tạo admin; người đăng ký đầu tiên tự do không bao giờ được nâng quyền
8. Admin tạo hai invite thường cho những người còn lại. Mỗi người có UID/passkey/state riêng
9. Đăng ký passkey/thiết bị dự phòng trước khi phụ thuộc vào một iPhone duy nhất

Không có endpoint public bootstrap, mật khẩu admin mặc định hay secret tự sinh lúc module khởi động.
`INVITE_ONLY=1`, `ALLOW_GUEST=0` là mặc định để dữ liệu nhóm không lẫn guest state.

## Push/timer tùy chọn

Nếu chưa cấu hình VAPID, endpoint push trả lỗi rõ `push_disabled`; tập và đồng bộ vẫn hoạt động.
Operator phải tự tạo/cất cặp khóa VAPID và cấu hình Worker secrets `VAPID_PUBLIC_KEY`,
`VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` (URL https hoặc mailto hợp lệ). Không đổi khóa bừa bãi:
subscription cũ gắn với public key cũ. Việc cấp/sử dụng secret và quyền notification cần được người dùng đồng ý.

Adapter dùng `web-push` để mã hóa RFC8291/VAPID rồi gửi bằng Workers fetch, không dùng Node HTTPS.
Chỉ cho phép hostname push của Apple/Google/Mozilla/Microsoft, HTTPS443, không redirect.
Alarm duy nhất luôn hẹn task sớm nhất; cancel/extend thay version/task bền vững, không dùng setTimeout
sau HTTP response. Mỗi lần xử lý giới hạn số subscription và outbound request.

Thông báo là **best effort**, không phải đồng hồ báo thức iOS chính xác. Task được claim bền vững
trước khi gửi để tránh duplicate sau alarm retry; crash sau claim hoặc lỗi push service có thể mất
thông báo. Các task/reminder còn lại vẫn được hẹn lại. Không có silent background sync.

## Kiểm thử nghiệm thu trên Free và iPhone thật (chưa thực hiện)

- Xác nhận tài khoản Workers Free, D1/SQLite DO Free, không đăng ký paid/R2
- Đo CPU/latency/errors của Worker và DO cho đăng ký/login và import gần 5 MiB;
  emulator không chứng minh giới hạn Free thực tế
- Safari đăng ký/login Face ID, reload giữ session; Add to Home Screen và login trong standalone
- Hai người không đọc/ghi state, passkey, admin hoặc subscription của nhau
- Hai thiết bị sửa offline cùng lúc, reconnect ra 409/merge và không mất workout
- A logout rồi B login trong hai tab; không có state của A trong B, kể cả request cũ đang chạy
- Cold-launch offline, force-kill, storage eviction: localStorage/cache không thay backup
- Trên iOS16.4+ Home Screen PWA, bấm trực tiếp để xin quyền notification; từ chối vẫn tập được
- Timer start/extend/cancel, khóa màn hình, redeploy, timezone/DST; không hứa thời điểm chuông tuyệt đối
- Service worker update không cache `/api/*`; kiểm tra version/build stamp mới
- Invite replay, challenge replay/expiry/wrong kind, logout-all, disabled user, stale passkey counter
- Nếu bật password, đo scrypt và memory thực tế; không giảm tham số nếu không đạt

Timer UI hiện không được lưu như dữ liệu server; force-kill không bảo đảm khôi phục countdown màn hình.
Push đã hẹn có thể vẫn đến. Các bài tập/nhật ký đã lưu giữ workflow offline upstream.

## Giới hạn Free và backup

Tại ngày 04/10/2026: Worker Free100k dynamic requests/ngày, 10ms CPU/request,128MB;
D1 Free5M rows read/100k rows write mỗi ngày,500MB/database,2MB/row;
SQLite DO Free có100k requests/ngày,13k GB-seconds/ngày và quota storage riêng.
Quota hết có thể làm API tạm lỗi, vì vậy app phải giữ pending sync và cho retry. Tài nguyên static
không chạy Worker thì không tốn dynamic-request quota. Không suy ra miễn phí tuyệt đối cho account
đã có gói trả phí hoặc tài nguyên khác.

D1 export định kỳ bằng công cụ operator; giữ riêng bản backup SESSION_SECRET/VAPID và kiểm tra restore.
Time Travel không thay backup độc lập. Export JSON trong app giữ dữ liệu tập, không xuất account/passkey.
Bản port này thiết lập instance mới; chưa có công cụ migrate nguyên `db.json` của server Node.
Có thể restore dữ liệu tập theo từng account qua import upstream. Không đổi RP ID rồi kỳ vọng passkey cũ hoạt động.

Nguồn chính thức:
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/
- https://developers.cloudflare.com/d1/platform/limits/
- https://developers.cloudflare.com/d1/platform/pricing/
- https://developers.cloudflare.com/durable-objects/platform/pricing/
- https://developers.cloudflare.com/durable-objects/api/alarms/
- https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/
- Quyền media: [NOTICE.md](../NOTICE.md); mã nguồn: [LICENSE](../LICENSE)
