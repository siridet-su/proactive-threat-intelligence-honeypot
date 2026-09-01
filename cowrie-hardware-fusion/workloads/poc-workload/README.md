# Fixed Pi PoC workload

โปรแกรม Go นี้มีเพียงสอง fixed modes สำหรับ controlled hardware PoC:

- `compute`: bounded SHA-256 work; ไม่ใช่ miner และไม่เชื่อม network
- `service`: HTTP server/client บน `127.0.0.1` ภายใน process/container เดียว

ทุก parameter มี hard upper bound ใน binary: duration 180 วินาที, workers 4,
requests 200/s และ work iterations 20,000 โปรแกรมรับเฉพาะ flags ที่ parse ได้และเขียน
JSON summary หนึ่งบรรทัด ไม่มี shell, file write, DNS หรือ outbound client target

Build ARM64 artifact:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false \
  -trimpath -ldflags='-s -w -buildid=' \
  -o poc-workload-linux-arm64 .
sha256sum poc-workload-linux-arm64
```

นำ hash ไปเป็น `IMPLEMENTATION_SHA256` ตอน build image เพื่อให้ runtime preflight ตรวจ
binary identity จาก OCI revision label ก่อนรัน
